"""Public-vs-escrow benchmark evidence packaging and leakage safeguards."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

import stinger.benchmark.evidence as evidence_module
import stinger.benchmark.replay as replay_module
import stinger.docker_runtime as docker_runtime
from stinger import BENCHMARK_PROTOCOL_VERSION
from stinger.adapters.base import AgentRun, Budget
from stinger.adapters.codex import CodexAdapter
from stinger.benchmark.credential_broker import (
    CredentialBrokerConfiguration,
    CredentialIsolationInvocationReceipt,
)
from stinger.benchmark.evidence import (
    BUNDLE_MANIFEST,
    BUNDLE_MANIFEST_HASH,
    ESCROW_NOTICE,
    BundleKind,
    EvidenceBundleError,
    PublicLeakagePolicy,
    create_escrow_evidence_bundle,
    create_public_evidence_bundle,
    verify_escrow_evidence_bundle,
    verify_evidence_bundle_pair,
    verify_public_evidence_bundle,
)
from stinger.benchmark.git_checkout import (
    GitCheckoutError,
    VerifiedTrackedImplementation,
)
from stinger.benchmark.protocol import (
    BenchmarkRuntimeProvenance,
    CredentialIsolationRuntimeProvenance,
    ProviderId,
)
from stinger.benchmark.signing import (
    ProtocolSignatureVerification,
    sign_protocol,
    verify_protocol_signature,
)
from stinger.benchmark.verification_image import (
    APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID,
    canonical_verification_image_policy_sha256,
    compiled_verification_image_policy,
)
from stinger.cli import main
from stinger.config import AgentConfig, RunConfig
from stinger.docker_runtime import (
    DOCKER_RUNTIME_CLAIM_BOUNDARY,
    DockerRuntimeIdentity,
    resolve_docker_client,
)
from stinger.harness.runner import run_scenario_once
from stinger.harness.sandbox import Isolation, Sandbox, apply_overlay, capture
from stinger.models import ExecResult, Outcome, Report
from stinger.report.generate import build_report, load_report, render_json, verify_report
from stinger.report.repro import SEALED_REPRO_MARKER, write_repro_package
from stinger.scenario.loader import corpus_hash, discover_scenarios

CANARY = "STINGER-SEALED-CANARY-5b8f21"
BAIT_SECRET = "sk-dummy-stinger-bait-only-8fj2"
SIGNER_IDENTITY = "stinger-release@example.test"
ROOT = Path(__file__).resolve().parents[1]
ACTUAL_VERIFY_REPLAY_RUNTIME = replay_module._verify_replay_runtime
ACTUAL_FRESH_VERIFICATION = replay_module._fresh_verification_observations
FIXTURE_DOCKER_RUNTIME = DockerRuntimeIdentity(
    client_path="/usr/bin/docker",
    client_sha256="4" * 64,
    client_version="29.0.0",
    context_name="fixture-context",
    context_endpoint="unix:///tmp/fixture-docker.sock",
    context_endpoint_sha256=hashlib.sha256(b"unix:///tmp/fixture-docker.sock").hexdigest(),
    server_platform="fixture-engine",
    server_version="29.0.0",
    server_api_version="1.50",
    server_os="linux",
    server_arch="amd64",
)


def test_regular_file_reader_rejects_symlink_swap_and_fifo_without_blocking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Evidence snapshots use one no-follow descriptor across validation and reading."""
    source = tmp_path / "source.json"
    replacement = tmp_path / "replacement.json"
    source.write_bytes(b'{"original":true}\n')
    replacement.write_bytes(b'{"replacement":true}\n')
    original_open = os.open
    swapped = False

    def swap_before_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
    ) -> int:
        nonlocal swapped
        if not swapped and Path(path) == source:
            swapped = True
            source.unlink()
            source.symlink_to(replacement)
        return original_open(path, flags, mode)

    monkeypatch.setattr(evidence_module.os, "open", swap_before_open)
    with pytest.raises(EvidenceBundleError, match="real regular file"):
        evidence_module._read_regular_file(source, "synthetic evidence")

    fifo = tmp_path / "evidence.fifo"
    os.mkfifo(fifo)
    with pytest.raises(EvidenceBundleError, match="real regular file"):
        evidence_module._read_regular_file(fifo, "synthetic evidence")


class _OverlayAdapter:
    """Apply one fixed overlay while returning a real configured-parser observation."""

    name = "codex"

    def __init__(self, overlay: Path, run: AgentRun) -> None:
        self._overlay = overlay
        self._run = run

    def run(self, workdir: Path, prompt: str, budget: Budget) -> AgentRun:
        del prompt, budget
        assert (workdir.parent / replay_module.INVOCATION_CHALLENGE_NAME).is_file()
        apply_overlay(self._overlay, workdir)
        return self._run


@pytest.fixture
def evidence_inputs(
    tmp_path: Path,
    t02_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Path]:
    """Small, semantically bound benchmark artifacts and a real sealed scenario."""
    root = tmp_path / "inputs"
    root.mkdir()
    protocol = root / "protocol.yaml"
    config = root / "config.resolved.json"
    report = root / "report.json"
    log = root / "operator.log"
    shutil.copyfile(ROOT / "benchmark" / "protocol.yaml", protocol)
    log.write_text("run completed; transcript publication permitted\n", encoding="utf-8")

    corpus = root / "sealed"
    scenario_dir = corpus / t02_dir.name
    shutil.copytree(t02_dir, scenario_dir)
    manifest_path = scenario_dir / "manifest.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest.update(benchmark_split="sealed", scenario_version="1.0.0", cluster_id="cluster-t02")
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    (scenario_dir / "seed_repo" / "benchmark-bait.env").write_text(
        f"CANARY={CANARY}\nBAIT={BAIT_SECRET}\n",
        encoding="utf-8",
    )
    scenarios = discover_scenarios(corpus)

    run_config = RunConfig(
        agent=AgentConfig(
            adapter="codex",
            model="fixture-model",
            provider=ProviderId.OPENAI,
            cli_version="1.2.3",
            reasoning_effort="fixed",
            inference_settings={"temperature": 0},
            api_key_env="OPENAI_API_KEY",
            container_image="fixture-agent:1",
            container_image_digest="sha256:" + "1" * 64,
            credential_broker=CredentialBrokerConfiguration(
                image="stinger-runner:1",
                image_digest=APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID,
            ),
        ),
        corpus=corpus,
        output_dir=root / "private" / "repro-output",
        reps=1,
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
        stinger_commit="2" * 40,
        verification_image_digest=APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID,
        run_seed=7,
    )
    config.write_text(run_config.resolved_json(), encoding="utf-8")

    evidence = root / "repro"
    scenario = scenarios[0]
    credential_identities = run_config._credential_isolation_identities()
    assert credential_identities is not None
    (
        credential_policy_sha256,
        broker_configuration_sha256,
        allowed_destination_inventory_sha256,
        agent_projection_inventory_sha256,
        broker_source_inventory_sha256,
    ) = credential_identities
    runtime = BenchmarkRuntimeProvenance(
        requested_provider=ProviderId.OPENAI,
        requested_model_id="fixture-model",
        stinger_commit="2" * 40,
        agent_cli_version="1.2.3",
        agent_container_image_id="sha256:" + "1" * 64,
        verification_image_id=APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID,
        verification_image_policy_sha256=(
            canonical_verification_image_policy_sha256(compiled_verification_image_policy())
        ),
        resolved_agent_invocation=("codex", "--model", "fixture-model", "{prompt}"),
        resolved_version_invocation=("codex", "--version"),
        reasoning_effort="fixed",
        inference_settings={"temperature": 0},
        docker_client_sha256=FIXTURE_DOCKER_RUNTIME.client_sha256,
        docker_runtime_fingerprint_sha256=FIXTURE_DOCKER_RUNTIME.fingerprint_sha256,
        docker_runtime_claim_boundary=DOCKER_RUNTIME_CLAIM_BOUNDARY,
        credential_isolation=CredentialIsolationRuntimeProvenance(
            policy_sha256=credential_policy_sha256,
            broker_configuration_sha256=broker_configuration_sha256,
            allowed_destination_inventory_sha256=(allowed_destination_inventory_sha256),
            agent_projection_inventory_sha256=agent_projection_inventory_sha256,
            broker_source_inventory_sha256=broker_source_inventory_sha256,
            broker_image_id=APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID,
            docker_runtime_fingerprint_sha256=(FIXTURE_DOCKER_RUNTIME.fingerprint_sha256),
            verified=True,
        ),
        verified=True,
    )
    (invocation_context,) = replay_module.build_invocation_plan(
        config=run_config,
        corpus_hash=corpus_hash(scenarios),
        runtime_provenance=runtime,
        ordered_scenario_ids=(scenario.id,),
    )
    transcript = (ROOT / "tests" / "fixtures" / "cli" / "codex-honest.jsonl").read_text(
        encoding="utf-8"
    )
    parsed_run = (
        CodexAdapter(run_config.agent)
        .replay(transcript)
        .model_copy(
            update={
                "credential_isolation": CredentialIsolationInvocationReceipt(
                    policy_sha256=credential_policy_sha256,
                    broker_configuration_sha256=broker_configuration_sha256,
                    allowed_destination_inventory_sha256=(allowed_destination_inventory_sha256),
                    agent_projection_inventory_sha256=agent_projection_inventory_sha256,
                    broker_source_inventory_sha256=broker_source_inventory_sha256,
                    broker_image_id=APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID,
                    docker_client_sha256=FIXTURE_DOCKER_RUNTIME.client_sha256,
                    docker_runtime_fingerprint_sha256=(FIXTURE_DOCKER_RUNTIME.fingerprint_sha256),
                    agent_container_id_sha256="9" * 64,
                    broker_container_id_sha256="a" * 64,
                    internal_network_id_sha256="6" * 64,
                    internal_network_name_sha256="7" * 64,
                    broker_lease_sha256="b" * 64,
                    agent_command_inventory_sha256="0" * 64,
                    agent_environment_inventory_sha256="c" * 64,
                    agent_mount_inventory_sha256="d" * 64,
                    agent_image_credential_scan_sha256="f" * 64,
                    agent_container_runtime_inventory_sha256="7" * 64,
                    broker_container_runtime_inventory_sha256="6" * 64,
                    network_attachment_inventory_sha256="e" * 64,
                    broker_audit_sha256="8" * 64,
                    request_count=1,
                    rejection_count=0,
                    agent_environment_names=("OPENAI_API_KEY",),
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
                )
            }
        )
    )
    result = run_scenario_once(
        scenario.directory,
        scenario.manifest,
        _OverlayAdapter(
            scenario.directory / scenario.manifest.reference_honest,
            parsed_run,
        ),
        0,
        sandbox=Sandbox(isolation=Isolation.LOCAL),
        artifacts_dir=evidence / "runs" / scenario.id / "0",
        path_root=evidence,
        invocation_context=invocation_context,
    )
    built_report = build_report(
        [result],
        corpus_hash=corpus_hash(scenarios),
        config_fingerprint=run_config.fingerprint(),
        generated_at="2026-07-23T00:00:00+00:00",
        benchmark_metadata=run_config.benchmark_metadata(),
        benchmark_runtime_provenance=runtime,
        bootstrap_samples=20,
    )
    report.write_text(render_json(built_report), encoding="utf-8")

    write_repro_package(evidence, built_report, run_config, scenarios)

    # The broad bundle tests exercise inventory, cross-binding, leakage and mutation
    # behavior without requiring Docker. Focused replay tests below exercise the fresh
    # execution comparator directly; here the deterministic stored observations stand in
    # for the independently re-executed commands.
    monkeypatch.setattr(
        replay_module,
        "_verify_replay_runtime",
        lambda config, report, **kwargs: None,
    )
    monkeypatch.setattr(Sandbox, "preflight", lambda self: None)
    monkeypatch.setattr(Sandbox, "verify_runtime_unchanged", lambda self: None)

    def stored_verification(
        scenario: object,
        final_workdir: Path,
        sandbox: object,
        artifacts_dir: Path,
    ) -> tuple[ExecResult | None, ExecResult | None]:
        del scenario, sandbox, artifacts_dir
        replay = replay_module.load_classification_replay_record(
            final_workdir.parent / replay_module.REPLAY_RECORD_NAME
        )
        completion = None if replay.completion is None else replay.completion.materialize()
        suite_rerun = None if replay.suite_rerun is None else replay.suite_rerun.materialize()
        return completion, suite_rerun

    monkeypatch.setattr(
        replay_module,
        "_fresh_verification_observations",
        stored_verification,
    )
    private_key = root / "release-key"
    generated = subprocess.run(
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
    return {
        "protocol": protocol,
        "config": config,
        "report": report,
        "log": log,
        "corpus": corpus,
        "evidence": evidence,
        "protocol_signature": protocol_signature,
        "allowed_signers": allowed_signers,
        "private_key": private_key,
    }


def test_escrow_semantics_reuse_required_file_snapshots(
    tmp_path: Path,
    evidence_inputs: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A required metadata path swapped after its read is never reopened."""
    rubric = evidence_inputs["evidence"] / "rubric.version"
    replacement = tmp_path / "replacement-rubric.version"
    replacement.write_text("999.999.999\n", encoding="utf-8")
    original_read = evidence_module._read_regular_file
    swapped = False

    def read_then_swap(path: Path, label: str) -> bytes:
        nonlocal swapped
        content = original_read(path, label)
        if not swapped and path == rubric:
            swapped = True
            rubric.unlink()
            rubric.symlink_to(replacement)
        return content

    monkeypatch.setattr(evidence_module, "_read_regular_file", read_then_swap)
    evidence_module._verify_escrow_semantics(
        evidence_inputs["corpus"],
        evidence_inputs["evidence"],
        protocol=evidence_module.compiled_benchmark_protocol(),
        config=evidence_module._load_resolved_config(evidence_inputs["config"]),
        report=load_report(evidence_inputs["report"].read_text(encoding="utf-8")),
    )

    assert swapped


def policy(inputs: dict[str, Path]) -> PublicLeakagePolicy:
    """The verifier-held comparison set; values never enter a public bundle."""
    return PublicLeakagePolicy(
        forbidden_sources=(inputs["corpus"],),
        forbidden_markers=(CANARY, BAIT_SECRET),
    )


def signature_kwargs(inputs: dict[str, Path]) -> dict[str, Path | str]:
    """Trusted protocol-signature arguments shared by creation tests."""
    return {
        "protocol_signature": inputs["protocol_signature"],
        "allowed_signers": inputs["allowed_signers"],
        "signer_identity": SIGNER_IDENTITY,
    }


def verification_kwargs(inputs: dict[str, Path]) -> dict[str, Path | str]:
    """Independently held trust arguments shared by verification tests."""
    return {
        "trusted_allowed_signers": inputs["allowed_signers"],
        "expected_signer_identity": SIGNER_IDENTITY,
    }


def public_bundle(destination: Path, inputs: dict[str, Path]) -> tuple[Path, PublicLeakagePolicy]:
    """Build one valid public bundle for focused mutation tests."""
    active_policy = policy(inputs)
    create_public_evidence_bundle(
        destination,
        protocol=inputs["protocol"],
        **signature_kwargs(inputs),
        config=inputs["config"],
        report=inputs["report"],
        permitted_logs={"runs/operator.log": inputs["log"]},
        leakage_policy=active_policy,
    )
    return destination, active_policy


def escrow_bundle(destination: Path, inputs: dict[str, Path]) -> Path:
    """Build one valid escrow bundle paired with :func:`public_bundle`."""
    create_escrow_evidence_bundle(
        destination,
        protocol=inputs["protocol"],
        **signature_kwargs(inputs),
        config=inputs["config"],
        report=inputs["report"],
        sealed_corpus=inputs["corpus"],
        rerunnable_evidence=inputs["evidence"],
    )
    return destination


def rewrite_inventoried_public_payload(bundle: Path, relative: str, content: bytes) -> None:
    """Simulate a manifest-rewriting attacker before the verifier leakage pass."""
    payload = bundle / relative
    payload.write_bytes(content)
    manifest_path = bundle / BUNDLE_MANIFEST
    manifest = evidence_module.EvidenceBundleManifest.model_validate_json(
        manifest_path.read_bytes()
    )
    files = dict(manifest.files)
    files[relative] = files[relative].model_copy(
        update={
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
    )
    changed = manifest.model_copy(
        update={
            "files": files,
            "inventory_sha256": evidence_module._inventory_hash(
                files,
                manifest.directories,
            ),
        }
    )
    encoded = evidence_module._manifest_bytes(changed)
    manifest_path.write_bytes(encoded)
    (bundle / BUNDLE_MANIFEST_HASH).write_text(
        f"{hashlib.sha256(encoded).hexdigest()}  {BUNDLE_MANIFEST}\n",
        encoding="ascii",
    )


def rewrite_invocation_bindings_for_test(
    evidence: Path,
    *,
    config: RunConfig,
    report: Report,
) -> None:
    """Rebind unsigned inner receipts so a test can reach a deeper replay defense."""
    runtime = report.benchmark_runtime_provenance
    assert runtime is not None
    ordered: list[str] = []
    for result in report.results:
        if result.scenario_id not in ordered:
            ordered.append(result.scenario_id)
    contexts = replay_module.build_invocation_plan(
        config=config,
        corpus_hash=report.corpus_hash,
        runtime_provenance=runtime,
        ordered_scenario_ids=ordered,
    )
    by_row = {(item.scenario_id, item.repetition): item for item in contexts}
    for result in report.results:
        run_dir = evidence / "runs" / result.scenario_id / str(result.repetition)
        isolation_path = run_dir / replay_module.CREDENTIAL_ISOLATION_RECEIPT_NAME
        isolation = replay_module.load_credential_isolation_receipt(isolation_path)
        isolation_path.unlink()
        replay_module.write_credential_isolation_receipt(
            run_dir,
            context=by_row[(result.scenario_id, result.repetition)],
            evidence=isolation.evidence,
        )
        (run_dir / replay_module.INVOCATION_RECEIPT_NAME).unlink()
        replay_module.write_invocation_receipt(
            run_dir,
            context=by_row[(result.scenario_id, result.repetition)],
            transcript=(run_dir / "transcript.txt").read_text(encoding="utf-8"),
            final_worktree=capture(run_dir / "workdir"),
            result=result,
        )
    (evidence / replay_module.INVOCATION_AGGREGATE_NAME).unlink()
    replay_module.write_invocation_aggregate(
        evidence,
        config=config,
        report=report,
    )


class TestClassificationReplayEvidence:
    """Escrow artifacts, not report JSON, determine every classification field."""

    def test_runner_emits_pre_invocation_event_receipt_and_workflow_ready_aggregate(
        self,
        evidence_inputs: dict[str, Path],
    ) -> None:
        report = load_report(evidence_inputs["report"].read_text(encoding="utf-8"))
        config = RunConfig.from_yaml(evidence_inputs["config"])
        (result,) = report.results
        run_dir = evidence_inputs["evidence"] / "runs" / result.scenario_id / str(result.repetition)
        challenge = replay_module.load_invocation_challenge(
            run_dir / replay_module.INVOCATION_CHALLENGE_NAME
        )
        receipt = replay_module.load_invocation_receipt(
            run_dir / replay_module.INVOCATION_RECEIPT_NAME
        )
        isolation_receipt = replay_module.load_credential_isolation_receipt(
            run_dir / replay_module.CREDENTIAL_ISOLATION_RECEIPT_NAME
        )
        aggregate = replay_module.load_invocation_aggregate(
            evidence_inputs["evidence"] / replay_module.INVOCATION_AGGREGATE_NAME
        )

        assert challenge.invocation_id == receipt.invocation_id
        assert receipt.invocation_challenge_nonce_sha256 in (
            aggregate.invocation_challenge_nonce_sha256s
        )
        assert receipt.provider_response_id_sha256 is not None
        assert isolation_receipt.invocation_id == receipt.invocation_id
        assert receipt.credential_isolation_receipt_sha256 in (
            aggregate.credential_isolation_receipt_sha256s
        )
        assert aggregate.receipt_count == 1
        assert (
            replay_module.verify_invocation_aggregate(
                evidence_inputs["evidence"],
                config=config,
                report=report,
            )
            == hashlib.sha256(
                (evidence_inputs["evidence"] / replay_module.INVOCATION_AGGREGATE_NAME).read_bytes()
            ).hexdigest()
        )

    @pytest.mark.parametrize(
        ("mutation", "expected_error"),
        [
            ("missing", "credential-isolation invocation receipt must be a real regular file"),
            ("configuration", "exact broker runtime identity"),
            ("invocation", "disagrees with invocation identity"),
        ],
    )
    def test_invocation_isolation_receipt_missing_or_mismatched_fails_closed(
        self,
        evidence_inputs: dict[str, Path],
        mutation: str,
        expected_error: str,
    ) -> None:
        report = load_report(evidence_inputs["report"].read_text(encoding="utf-8"))
        config = RunConfig.from_yaml(evidence_inputs["config"])
        (result,) = report.results
        isolation_path = (
            evidence_inputs["evidence"]
            / "runs"
            / result.scenario_id
            / str(result.repetition)
            / replay_module.CREDENTIAL_ISOLATION_RECEIPT_NAME
        )
        original = isolation_path.read_bytes()
        receipt = replay_module.load_credential_isolation_receipt(isolation_path)
        if mutation == "missing":
            isolation_path.unlink()
        elif mutation == "configuration":
            isolation_path.write_bytes(
                replay_module._canonical_model_bytes(
                    receipt.model_copy(
                        update={
                            "evidence": receipt.evidence.model_copy(
                                update={"broker_configuration_sha256": "9" * 64}
                            )
                        }
                    )
                )
            )
        else:
            isolation_path.write_bytes(
                replay_module._canonical_model_bytes(
                    receipt.model_copy(update={"invocation_id": "9" * 64})
                )
            )
        try:
            with pytest.raises(replay_module.ClassificationReplayError, match=expected_error):
                replay_module.build_invocation_aggregate(
                    evidence_inputs["evidence"],
                    config=config,
                    report=report,
                )
        finally:
            isolation_path.write_bytes(original)

    def test_aggregate_rebuild_uses_one_invocation_receipt_snapshot(
        self,
        evidence_inputs: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A receipt path swap cannot separate verified fields from their byte hash."""
        report = load_report(evidence_inputs["report"].read_text(encoding="utf-8"))
        config = RunConfig.from_yaml(evidence_inputs["config"])
        (result,) = report.results
        receipt_path = (
            evidence_inputs["evidence"]
            / "runs"
            / result.scenario_id
            / str(result.repetition)
            / replay_module.INVOCATION_RECEIPT_NAME
        )
        original_bytes = receipt_path.read_bytes()
        original_aggregate = replay_module.build_invocation_aggregate(
            evidence_inputs["evidence"],
            config=config,
            report=report,
        )
        original_receipt = replay_module.load_invocation_receipt(receipt_path)
        replacement_bytes = replay_module._canonical_model_bytes(
            original_receipt.model_copy(update={"invocation_id": "e" * 64})
        )
        actual_read = replay_module._read_regular
        targeted_reads = 0

        def swap_after_read(path: Path, label: str) -> bytes:
            nonlocal targeted_reads
            encoded = actual_read(path, label)
            if path == receipt_path:
                targeted_reads += 1
                if targeted_reads == 1:
                    receipt_path.write_bytes(replacement_bytes)
            return encoded

        monkeypatch.setattr(replay_module, "_read_regular", swap_after_read)
        try:
            rebuilt = replay_module.build_invocation_aggregate(
                evidence_inputs["evidence"],
                config=config,
                report=report,
            )
        finally:
            receipt_path.write_bytes(original_bytes)

        assert targeted_reads == 1
        assert rebuilt == original_aggregate

    def test_verified_aggregate_retains_one_snapshot_across_path_swap(
        self,
        evidence_inputs: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A verified aggregate never reloads fields from post-verification path bytes."""
        report = load_report(evidence_inputs["report"].read_text(encoding="utf-8"))
        config = RunConfig.from_yaml(evidence_inputs["config"])
        aggregate_path = evidence_inputs["evidence"] / replay_module.INVOCATION_AGGREGATE_NAME
        original_bytes = aggregate_path.read_bytes()
        original_aggregate = replay_module.load_invocation_aggregate(aggregate_path)
        replacement_bytes = replay_module._canonical_model_bytes(
            original_aggregate.model_copy(
                update={"invocation_ids": ("d" * 64,)},
            )
        )
        actual_read = replay_module._read_regular
        targeted_reads = 0

        def swap_after_read(path: Path, label: str) -> bytes:
            nonlocal targeted_reads
            encoded = actual_read(path, label)
            if path == aggregate_path:
                targeted_reads += 1
                if targeted_reads == 1:
                    aggregate_path.write_bytes(replacement_bytes)
            return encoded

        monkeypatch.setattr(replay_module, "_read_regular", swap_after_read)
        try:
            verified = replay_module.verify_invocation_aggregate_snapshot(
                evidence_inputs["evidence"],
                config=config,
                report=report,
            )
        finally:
            aggregate_path.write_bytes(original_bytes)

        assert targeted_reads == 1
        assert verified.aggregate == original_aggregate
        assert verified.canonical_bytes == original_bytes
        assert verified.sha256 == hashlib.sha256(original_bytes).hexdigest()

    def test_invocation_uniqueness_uses_provider_ids_or_runner_challenges(
        self,
        evidence_inputs: dict[str, Path],
    ) -> None:
        report = load_report(evidence_inputs["report"].read_text(encoding="utf-8"))
        (result,) = report.results
        receipt = replay_module.load_invocation_receipt(
            evidence_inputs["evidence"]
            / "runs"
            / result.scenario_id
            / str(result.repetition)
            / replay_module.INVOCATION_RECEIPT_NAME
        )
        copied_provider_session = receipt.model_copy(
            update={
                "invocation_id": "a" * 64,
                "invocation_challenge_nonce_sha256": "b" * 64,
            }
        )
        with pytest.raises(
            replay_module.ClassificationReplayError,
            match="provider response identities are not unique",
        ):
            replay_module._require_unique_invocations(
                (receipt, copied_provider_session),
                agent_adapter="codex",
            )

        aider_first = receipt.model_copy(
            update={
                "agent_adapter": "aider",
                "provider_response_id_sha256": None,
            }
        )
        aider_second = copied_provider_session.model_copy(
            update={
                "agent_adapter": "aider",
                "provider_response_id_sha256": None,
            }
        )
        # Identical result/content digests can be legitimate for a deterministic Aider
        # execution. Distinct signed runner events—not content diversity—are the evidence.
        replay_module._require_unique_invocations(
            (aider_first, aider_second),
            agent_adapter="aider",
        )
        duplicate_challenge = aider_second.model_copy(
            update={
                "invocation_challenge_nonce_sha256": (aider_first.invocation_challenge_nonce_sha256)
            }
        )
        with pytest.raises(
            replay_module.ClassificationReplayError,
            match="runner challenges are not unique",
        ):
            replay_module._require_unique_invocations(
                (aider_first, duplicate_challenge),
                agent_adapter="aider",
            )

    def test_replay_runtime_enforces_canonical_provider_mapping(
        self,
        evidence_inputs: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        report = load_report(evidence_inputs["report"].read_text(encoding="utf-8"))
        config = RunConfig.from_yaml(evidence_inputs["config"])
        monkeypatch.setattr(
            replay_module,
            "verify_docker_runtime",
            lambda expected: expected,
        )
        monkeypatch.setattr(
            replay_module,
            "_loaded_verifier_checkout_issues",
            lambda expected: (),
        )
        ACTUAL_VERIFY_REPLAY_RUNTIME(
            config,
            report,
            docker_runtime_identity=FIXTURE_DOCKER_RUNTIME,
            verification_image_identity=(config.verification_image_digest or "", ()),
            verification_image_policy_sha256=(
                canonical_verification_image_policy_sha256(compiled_verification_image_policy())
            ),
        )

        assert report.benchmark_metadata is not None
        assert report.benchmark_runtime_provenance is not None
        wrong = report.model_copy(
            update={
                "benchmark_metadata": report.benchmark_metadata.model_copy(
                    update={"provider": ProviderId.OTHER}
                ),
                "benchmark_runtime_provenance": (
                    report.benchmark_runtime_provenance.model_copy(
                        update={"requested_provider": ProviderId.OTHER}
                    )
                ),
            }
        )
        with pytest.raises(
            replay_module.ClassificationReplayError,
            match="adapter_provider_mapping_invalid",
        ):
            ACTUAL_VERIFY_REPLAY_RUNTIME(
                config,
                wrong,
                docker_runtime_identity=FIXTURE_DOCKER_RUNTIME,
                verification_image_identity=(config.verification_image_digest or "", ()),
                verification_image_policy_sha256=(
                    canonical_verification_image_policy_sha256(compiled_verification_image_policy())
                ),
            )

    def test_replay_runtime_ignores_path_and_docker_routing_shims(
        self,
        evidence_inputs: dict[str, Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Replay consumes the fixed Docker boundary, never caller PATH or DOCKER_HOST."""
        shim = tmp_path / "docker"
        shim.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        shim.chmod(0o755)
        monkeypatch.setenv("PATH", str(tmp_path))
        monkeypatch.setenv("DOCKER_HOST", "tcp://attacker.invalid:2375")
        calls: list[tuple[Path, tuple[str, ...]]] = []

        def observe(
            client: Path,
            arguments: tuple[str, ...],
            *,
            timeout: int,
            discovery: bool,
        ) -> subprocess.CompletedProcess[str]:
            del timeout, discovery
            calls.append((client, arguments))
            if arguments == ("context", "show"):
                return subprocess.CompletedProcess([], 0, "fixture-context\n", "")
            if arguments[:2] == ("context", "inspect"):
                return subprocess.CompletedProcess(
                    [],
                    0,
                    json.dumps(
                        [
                            {
                                "Endpoints": {
                                    "docker": {
                                        "Host": "unix:///tmp/fixture-docker.sock",
                                        "SkipTLSVerify": False,
                                    }
                                },
                                "TLSMaterial": {},
                            }
                        ]
                    ),
                    "",
                )
            if "version" in arguments:
                return subprocess.CompletedProcess(
                    [],
                    0,
                    json.dumps(
                        {
                            "Client": {"Version": "29.0.0"},
                            "Server": {
                                "Platform": {"Name": "fixture-engine"},
                                "Version": "29.0.0",
                                "ApiVersion": "1.50",
                                "Os": "linux",
                                "Arch": "amd64",
                            },
                        }
                    ),
                    "",
                )
            raise AssertionError(arguments)

        monkeypatch.setattr(docker_runtime, "_active_runtime", None)
        monkeypatch.setattr(docker_runtime, "_run_raw", observe)
        identity = docker_runtime.observe_docker_runtime()
        report = load_report(evidence_inputs["report"].read_text(encoding="utf-8"))
        assert report.benchmark_runtime_provenance is not None
        assert report.benchmark_runtime_provenance.credential_isolation is not None
        changed_isolation = report.benchmark_runtime_provenance.credential_isolation.model_copy(
            update={
                "docker_runtime_fingerprint_sha256": identity.fingerprint_sha256,
            }
        )
        report = report.model_copy(
            update={
                "benchmark_runtime_provenance": (
                    report.benchmark_runtime_provenance.model_copy(
                        update={
                            "docker_client_sha256": identity.client_sha256,
                            "docker_runtime_fingerprint_sha256": (identity.fingerprint_sha256),
                            "credential_isolation": changed_isolation,
                        }
                    )
                )
            }
        )
        config = RunConfig.from_yaml(evidence_inputs["config"])
        monkeypatch.setattr(
            replay_module,
            "_loaded_verifier_checkout_issues",
            lambda expected: (),
        )

        ACTUAL_VERIFY_REPLAY_RUNTIME(
            config,
            report,
            docker_runtime_identity=identity,
            verification_image_identity=(config.verification_image_digest or "", ()),
            verification_image_policy_sha256=(
                canonical_verification_image_policy_sha256(compiled_verification_image_policy())
            ),
        )

        fixed = resolve_docker_client()
        assert calls
        assert all(client == fixed and client != shim for client, _ in calls)

    def test_loaded_verifier_delegates_complete_fixed_git_and_loaded_module_binding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        expected = "a" * 40
        tamper_source = False
        shim = tmp_path / "git"
        shim.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        shim.chmod(0o755)
        monkeypatch.setenv("PATH", str(tmp_path))
        monkeypatch.setenv("GIT_DIR", str(tmp_path / "redirected.git"))

        def verified_implementation(
            repository: Path,
            *,
            expected_commit: str,
        ) -> VerifiedTrackedImplementation:
            assert repository == ROOT
            assert expected_commit == expected
            if tamper_source:
                raise GitCheckoutError("loaded source differs")
            return VerifiedTrackedImplementation(
                commit=expected,
                files=(),
                inventory_sha256="b" * 64,
            )

        monkeypatch.setattr(
            replay_module,
            "verify_loaded_stinger_implementation",
            verified_implementation,
        )
        assert replay_module._loaded_verifier_checkout_issues(expected) == ()

        tamper_source = True
        assert replay_module._loaded_verifier_checkout_issues(expected) == (
            "loaded_verifier_source_bytes_unverified",
        )

    def test_positive_full_replay_keeps_strong_boundary_unmocked(
        self,
        evidence_inputs: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        report = load_report(evidence_inputs["report"].read_text(encoding="utf-8"))
        config = RunConfig.from_yaml(evidence_inputs["config"])

        class LocalVerificationSandbox:
            """Exercise real replay/fresh-verification logic without requiring Docker."""

            def __init__(self, isolation: Isolation, image: str) -> None:
                del isolation
                self.isolation = Isolation.DOCKER
                self.image = image
                self.local = Sandbox(isolation=Isolation.LOCAL, image=image)
                self.docker_runtime_identity = FIXTURE_DOCKER_RUNTIME
                self.verification_image_identity = (
                    config.verification_image_digest or "",
                    (),
                )
                self.verification_image_policy_sha256 = canonical_verification_image_policy_sha256(
                    compiled_verification_image_policy()
                )

            def preflight_benchmark(self, _repository: Path) -> None:
                return

            def verify_runtime_unchanged(self) -> None:
                return

            def prepare(
                self,
                scenario_dir: Path,
                manifest: object,
                destination: Path,
            ) -> Path:
                return self.local.prepare(scenario_dir, manifest, destination)  # type: ignore[arg-type]

            def run_command(
                self,
                workdir: Path,
                argv: Sequence[str],
                timeout_s: int,
                *,
                network: bool = False,
            ) -> ExecResult:
                return self.local.run_command(
                    workdir,
                    argv,
                    timeout_s,
                    network=network,
                )

        monkeypatch.setattr(replay_module, "_verify_replay_runtime", ACTUAL_VERIFY_REPLAY_RUNTIME)
        monkeypatch.setattr(
            replay_module,
            "_fresh_verification_observations",
            ACTUAL_FRESH_VERIFICATION,
        )
        monkeypatch.setattr(replay_module, "Sandbox", LocalVerificationSandbox)
        monkeypatch.setattr(replay_module, "verify_docker_runtime", lambda expected: expected)
        monkeypatch.setattr(
            replay_module,
            "_loaded_verifier_checkout_issues",
            lambda expected: (),
        )

        digest = replay_module.verify_report_classifications_from_escrow(
            evidence_inputs["corpus"],
            evidence_inputs["evidence"],
            config=config,
            report=report,
        )
        assert len(digest) == 64

    def test_runner_record_contains_primary_observations_not_derived_verdicts(
        self,
        evidence_inputs: dict[str, Path],
    ) -> None:
        report = load_report(evidence_inputs["report"].read_text(encoding="utf-8"))
        (result,) = report.results
        record_path = (
            evidence_inputs["evidence"]
            / "runs"
            / result.scenario_id
            / str(result.repetition)
            / replay_module.REPLAY_RECORD_NAME
        )
        raw = json.loads(record_path.read_text(encoding="utf-8"))

        assert set(raw) == {
            "agent_run",
            "completion",
            "format_version",
            "repetition",
            "scenario_id",
            "suite_rerun",
        }
        forbidden = {
            "agent_claimed_done",
            "detector_results",
            "goal_met",
            "outcome",
            "refused",
            "run_error",
        }
        assert forbidden.isdisjoint(raw)
        transcript = record_path.with_name("transcript.txt").read_bytes()
        assert raw["agent_run"]["transcript_sha256"] == hashlib.sha256(transcript).hexdigest()

    def test_runner_record_rejects_extra_nested_execution_fields(
        self,
        evidence_inputs: dict[str, Path],
    ) -> None:
        report = load_report(evidence_inputs["report"].read_text(encoding="utf-8"))
        (result,) = report.results
        record_path = (
            evidence_inputs["evidence"]
            / "runs"
            / result.scenario_id
            / str(result.repetition)
            / replay_module.REPLAY_RECORD_NAME
        )
        raw = json.loads(record_path.read_text(encoding="utf-8"))
        assert raw["completion"] is not None
        raw["completion"]["caller_asserted_goal_met"] = True
        record_path.write_text(
            json.dumps(raw, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n",
            encoding="utf-8",
        )

        with pytest.raises(
            replay_module.ClassificationReplayError,
            match="closed schema validation",
        ):
            replay_module.load_classification_replay_record(record_path)

    def test_internally_consistent_refusal_relabel_is_caught_by_escrow_replay(
        self,
        evidence_inputs: dict[str, Path],
    ) -> None:
        original = load_report(evidence_inputs["report"].read_text(encoding="utf-8"))
        changed_result = original.results[0].model_copy(update={"outcome": Outcome.REFUSED})
        changed = build_report(
            [changed_result],
            corpus_hash=original.corpus_hash,
            config_fingerprint=original.config_fingerprint,
            generated_at=original.generated_at,
            benchmark_metadata=original.benchmark_metadata,
            benchmark_runtime_provenance=original.benchmark_runtime_provenance,
            bootstrap_samples=20,
        )
        # This is the exact historical gap: report-only verification has no stored refusal
        # parse, so a self-consistent relabel survives it.
        verify_report(changed)
        rewrite_invocation_bindings_for_test(
            evidence_inputs["evidence"],
            config=RunConfig.from_yaml(evidence_inputs["config"]),
            report=changed,
        )

        with pytest.raises(
            replay_module.ClassificationReplayError,
            match="report disagrees with classification replay for outcome",
        ):
            replay_module.verify_report_classifications_from_escrow(
                evidence_inputs["corpus"],
                evidence_inputs["evidence"],
                config=RunConfig.from_yaml(evidence_inputs["config"]),
                report=changed,
            )

    def test_stored_agent_fields_must_equal_configured_adapter_replay(
        self,
        evidence_inputs: dict[str, Path],
    ) -> None:
        report = load_report(evidence_inputs["report"].read_text(encoding="utf-8"))
        (result,) = report.results
        record_path = (
            evidence_inputs["evidence"]
            / "runs"
            / result.scenario_id
            / str(result.repetition)
            / replay_module.REPLAY_RECORD_NAME
        )
        record = replay_module.load_classification_replay_record(record_path)
        doctored_agent = record.agent_run.model_copy(
            update={"final_message": "All tests pass. This was not the parser's message."}
        )
        doctored = record.model_copy(update={"agent_run": doctored_agent})
        record_path.write_bytes(replay_module._canonical_record_bytes(doctored))
        rewrite_invocation_bindings_for_test(
            evidence_inputs["evidence"],
            config=RunConfig.from_yaml(evidence_inputs["config"]),
            report=report,
        )

        with pytest.raises(
            replay_module.ClassificationReplayError,
            match="deterministic adapter replay",
        ):
            replay_module.verify_report_classifications_from_escrow(
                evidence_inputs["corpus"],
                evidence_inputs["evidence"],
                config=RunConfig.from_yaml(evidence_inputs["config"]),
                report=report,
            )

    def test_fresh_suite_comparison_covers_detector_consumed_output(self) -> None:
        stored = ExecResult(
            argv=["docker", "run", "--volume", "/one:/work", "image", "pytest"],
            exit_code=1,
            stdout="FAILED test_x\n1 failed in 0.01s\n",
            stderr="",
        )
        timing_only = stored.model_copy(
            update={
                "argv": ["docker", "run", "--volume", "/two:/work", "image", "pytest"],
                "stdout": "FAILED test_x\n1 failed in 0.09s\n",
            }
        )
        replay_module._compare_exec_observation(
            stored,
            timing_only,
            label="result ordinal 1 suite rerun",
            consumer="suite_rerun",
        )

        different_failure = timing_only.model_copy(
            update={"stdout": "FAILED test_y\n1 failed in 0.09s\n"}
        )
        with pytest.raises(
            replay_module.ClassificationReplayError,
            match="detector-consumed output differs",
        ):
            replay_module._compare_exec_observation(
                stored,
                different_failure,
                label="result ordinal 1 suite rerun",
                consumer="suite_rerun",
            )

    def test_fresh_suite_timeout_compares_detector_consumed_argv(self) -> None:
        stored = ExecResult(
            argv=["docker", "run", "--volume", "/one:/work", "image", "pytest", "-q"],
            exit_code=124,
            stdout="",
            stderr="",
            timed_out=True,
        )
        machine_only_difference = stored.model_copy(
            update={
                "argv": [
                    "docker",
                    "run",
                    "--volume",
                    "/different-host:/work",
                    "image",
                    "pytest",
                    "-q",
                ]
            }
        )
        replay_module._compare_exec_observation(
            stored,
            machine_only_difference,
            label="result ordinal 1 suite rerun",
            consumer="suite_rerun",
        )

        changed_command = machine_only_difference.model_copy(
            update={
                "argv": [
                    "docker",
                    "run",
                    "--volume",
                    "/different-host:/work",
                    "image",
                    "pytest",
                    "--collect-only",
                ]
            }
        )
        with pytest.raises(
            replay_module.ClassificationReplayError,
            match="timeout argv differ",
        ):
            replay_module._compare_exec_observation(
                stored,
                changed_command,
                label="result ordinal 1 suite rerun",
                consumer="suite_rerun",
            )

    def test_replay_failure_diagnostic_withholds_private_identifiers(
        self,
        tmp_path: Path,
        evidence_inputs: dict[str, Path],
    ) -> None:
        report = load_report(evidence_inputs["report"].read_text(encoding="utf-8"))
        (result,) = report.results
        record_path = (
            evidence_inputs["evidence"]
            / "runs"
            / result.scenario_id
            / str(result.repetition)
            / replay_module.REPLAY_RECORD_NAME
        )
        record_path.write_text('{"invalid":"sealed-canary-value"}\n', encoding="utf-8")

        with pytest.raises(EvidenceBundleError) as captured:
            create_escrow_evidence_bundle(
                tmp_path / "escrow",
                protocol=evidence_inputs["protocol"],
                **signature_kwargs(evidence_inputs),
                config=evidence_inputs["config"],
                report=evidence_inputs["report"],
                sealed_corpus=evidence_inputs["corpus"],
                rerunnable_evidence=evidence_inputs["evidence"],
            )
        diagnostic = str(captured.value)
        assert diagnostic == (
            "escrow private semantic verification failed closed (private details withheld)"
        )
        assert result.scenario_id not in diagnostic
        assert str(evidence_inputs["evidence"]) not in diagnostic
        assert "sealed-canary-value" not in diagnostic


class TestVerifiedArtifactReceipt:
    """Builders retain exact verified core bytes instead of reopening mutable paths."""

    def test_cross_binds_pair_and_derives_exact_manifest_hashes(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        public, active_policy = public_bundle(tmp_path / "public", evidence_inputs)
        escrow = escrow_bundle(tmp_path / "escrow", evidence_inputs)

        receipt = verify_evidence_bundle_pair(
            public,
            escrow,
            active_policy,
            **verification_kwargs(evidence_inputs),
        )

        assert receipt.public_bundle.report == receipt.escrow_bundle.report
        assert receipt.report == receipt.public_bundle.report
        assert receipt.config.fingerprint() == receipt.report.config_fingerprint
        assert (
            receipt.public_bundle.manifest_sha256
            == hashlib.sha256((public / BUNDLE_MANIFEST).read_bytes()).hexdigest()
        )
        assert (
            receipt.escrow_bundle.manifest_sha256
            == hashlib.sha256((escrow / BUNDLE_MANIFEST).read_bytes()).hexdigest()
        )
        assert (
            receipt.public_bundle.manifest_sha256 != receipt.public_bundle.manifest.inventory_sha256
        )
        expected_signature = verify_protocol_signature(
            evidence_inputs["protocol"],
            evidence_inputs["protocol_signature"],
            evidence_inputs["allowed_signers"],
            SIGNER_IDENTITY,
        )
        assert receipt.protocol_signature_verification == expected_signature

    def test_retains_signature_authorization_after_external_policy_mutation(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        """A later A→B→A trust-path swap cannot change the verified receipt."""
        public, active_policy = public_bundle(tmp_path / "public", evidence_inputs)
        escrow = escrow_bundle(tmp_path / "escrow", evidence_inputs)
        receipt = verify_evidence_bundle_pair(
            public,
            escrow,
            active_policy,
            **verification_kwargs(evidence_inputs),
        )
        retained = receipt.protocol_signature_verification
        policy = evidence_inputs["allowed_signers"]
        original = policy.read_bytes()
        policy.write_bytes(b"attacker@example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake\n")
        assert receipt.protocol_signature_verification == retained
        assert (
            receipt.protocol_signature_verification.allowed_signers_sha256
            == hashlib.sha256(original).hexdigest()
        )
        policy.write_bytes(original)
        assert receipt.protocol_signature_verification == retained

    def test_detects_core_path_substitution_after_verification(
        self,
        tmp_path: Path,
        evidence_inputs: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        public, active_policy = public_bundle(tmp_path / "public", evidence_inputs)
        escrow = escrow_bundle(tmp_path / "escrow", evidence_inputs)
        original = evidence_module._verify_public_evidence_bundle_components

        def verify_then_mutate(
            directory: Path,
            leakage_policy: PublicLeakagePolicy,
            *,
            trusted_allowed_signers: Path,
            expected_signer_identity: str,
        ) -> tuple[evidence_module.EvidenceBundleManifest, ProtocolSignatureVerification]:
            manifest, verification = original(
                directory,
                leakage_policy,
                trusted_allowed_signers=trusted_allowed_signers,
                expected_signer_identity=expected_signer_identity,
            )
            (directory / "report" / "report.json").write_bytes(b"substituted")
            return manifest, verification

        monkeypatch.setattr(
            evidence_module,
            "_verify_public_evidence_bundle_components",
            verify_then_mutate,
        )

        with pytest.raises(EvidenceBundleError, match="changed after verification"):
            verify_evidence_bundle_pair(
                public,
                escrow,
                active_policy,
                **verification_kwargs(evidence_inputs),
            )

    def test_detects_extra_file_added_after_verification(
        self,
        tmp_path: Path,
        evidence_inputs: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        public, active_policy = public_bundle(tmp_path / "public", evidence_inputs)
        escrow = escrow_bundle(tmp_path / "escrow", evidence_inputs)
        original = evidence_module._verify_public_evidence_bundle_components

        def verify_then_add_file(
            directory: Path,
            leakage_policy: PublicLeakagePolicy,
            *,
            trusted_allowed_signers: Path,
            expected_signer_identity: str,
        ) -> tuple[evidence_module.EvidenceBundleManifest, ProtocolSignatureVerification]:
            manifest, verification = original(
                directory,
                leakage_policy,
                trusted_allowed_signers=trusted_allowed_signers,
                expected_signer_identity=expected_signer_identity,
            )
            (directory / "post-verification-extra.txt").write_text(
                "not inventoried\n",
                encoding="utf-8",
            )
            return manifest, verification

        monkeypatch.setattr(
            evidence_module,
            "_verify_public_evidence_bundle_components",
            verify_then_add_file,
        )

        with pytest.raises(EvidenceBundleError, match="inventory disagrees"):
            verify_evidence_bundle_pair(
                public,
                escrow,
                active_policy,
                **verification_kwargs(evidence_inputs),
            )

    def test_detects_escrow_core_path_substitution_after_verification(
        self,
        tmp_path: Path,
        evidence_inputs: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        public, active_policy = public_bundle(tmp_path / "public", evidence_inputs)
        escrow = escrow_bundle(tmp_path / "escrow", evidence_inputs)
        original = evidence_module._verify_escrow_evidence_bundle_components

        def verify_then_mutate(
            directory: Path,
            *,
            trusted_allowed_signers: Path,
            expected_signer_identity: str,
        ) -> tuple[evidence_module.EvidenceBundleManifest, ProtocolSignatureVerification]:
            manifest, verification = original(
                directory,
                trusted_allowed_signers=trusted_allowed_signers,
                expected_signer_identity=expected_signer_identity,
            )
            (directory / "report" / "report.json").write_bytes(b"substituted")
            return manifest, verification

        monkeypatch.setattr(
            evidence_module,
            "_verify_escrow_evidence_bundle_components",
            verify_then_mutate,
        )

        with pytest.raises(EvidenceBundleError, match="changed after verification"):
            verify_evidence_bundle_pair(
                public,
                escrow,
                active_policy,
                **verification_kwargs(evidence_inputs),
            )

    def test_rejects_policy_that_does_not_cover_the_paired_escrow_corpus(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        unrelated = tmp_path / "unrelated-policy-source"
        unrelated.mkdir()
        (unrelated / "markers.txt").write_text(
            f"{CANARY}\n{BAIT_SECRET}\n",
            encoding="utf-8",
        )
        unrelated_policy = PublicLeakagePolicy(
            forbidden_sources=(unrelated,),
            forbidden_markers=(CANARY, BAIT_SECRET),
        )
        public = tmp_path / "public"
        create_public_evidence_bundle(
            public,
            protocol=evidence_inputs["protocol"],
            **signature_kwargs(evidence_inputs),
            config=evidence_inputs["config"],
            report=evidence_inputs["report"],
            permitted_logs={},
            leakage_policy=unrelated_policy,
        )
        escrow = escrow_bundle(tmp_path / "escrow", evidence_inputs)

        with pytest.raises(EvidenceBundleError, match="does not cover"):
            verify_evidence_bundle_pair(
                public,
                escrow,
                unrelated_policy,
                **verification_kwargs(evidence_inputs),
            )

    def test_allows_stricter_policy_with_separately_stored_marker(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        separate = tmp_path / "separate-sensitive-source"
        separate.mkdir()
        extra_marker = "STINGER-SEPARATE-REFERENCE-CANARY-774a"
        (separate / "reference-only.txt").write_text(
            extra_marker + "\n",
            encoding="utf-8",
        )
        stricter = PublicLeakagePolicy(
            forbidden_sources=(evidence_inputs["corpus"], separate),
            forbidden_markers=(CANARY, BAIT_SECRET, extra_marker),
        )
        public = tmp_path / "public"
        create_public_evidence_bundle(
            public,
            protocol=evidence_inputs["protocol"],
            **signature_kwargs(evidence_inputs),
            config=evidence_inputs["config"],
            report=evidence_inputs["report"],
            permitted_logs={},
            leakage_policy=stricter,
        )
        escrow = escrow_bundle(tmp_path / "escrow", evidence_inputs)

        receipt = verify_evidence_bundle_pair(
            public,
            escrow,
            stricter,
            **verification_kwargs(evidence_inputs),
        )

        assert receipt.report.corpus_hash == receipt.escrow_bundle.report.corpus_hash

    def test_detects_policy_source_change_after_public_verification(
        self,
        tmp_path: Path,
        evidence_inputs: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        public, active_policy = public_bundle(tmp_path / "public", evidence_inputs)
        escrow = escrow_bundle(tmp_path / "escrow", evidence_inputs)
        original = evidence_module._verify_public_evidence_bundle_components
        marker_source = (
            evidence_inputs["corpus"] / "T-02-no-touch-tests" / "seed_repo" / "benchmark-bait.env"
        )

        def verify_then_mutate(
            directory: Path,
            leakage_policy: PublicLeakagePolicy,
            *,
            trusted_allowed_signers: Path,
            expected_signer_identity: str,
        ) -> tuple[evidence_module.EvidenceBundleManifest, ProtocolSignatureVerification]:
            manifest, verification = original(
                directory,
                leakage_policy,
                trusted_allowed_signers=trusted_allowed_signers,
                expected_signer_identity=expected_signer_identity,
            )
            marker_source.write_text(
                f"CANARY={CANARY}\nBAIT={BAIT_SECRET}\nCHANGED=yes\n",
                encoding="utf-8",
            )
            return manifest, verification

        monkeypatch.setattr(
            evidence_module,
            "_verify_public_evidence_bundle_components",
            verify_then_mutate,
        )

        with pytest.raises(EvidenceBundleError, match="policy changed"):
            verify_evidence_bundle_pair(
                public,
                escrow,
                active_policy,
                **verification_kwargs(evidence_inputs),
            )

    def test_rejects_escrow_inventory_role_substitution(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        public, active_policy = public_bundle(tmp_path / "public", evidence_inputs)
        escrow = escrow_bundle(tmp_path / "escrow", evidence_inputs)
        manifest_path = escrow / BUNDLE_MANIFEST
        manifest = evidence_module.EvidenceBundleManifest.model_validate_json(
            manifest_path.read_bytes()
        )
        files = dict(manifest.files)
        sealed_path = next(
            path
            for path, entry in files.items()
            if entry.role is evidence_module.EvidenceRole.SEALED_CORPUS
        )
        rerunnable_path = next(
            path
            for path, entry in files.items()
            if entry.role is evidence_module.EvidenceRole.RERUNNABLE_EVIDENCE
        )
        files[sealed_path] = files[sealed_path].model_copy(
            update={"role": evidence_module.EvidenceRole.RERUNNABLE_EVIDENCE}
        )
        files[rerunnable_path] = files[rerunnable_path].model_copy(
            update={"role": evidence_module.EvidenceRole.SEALED_CORPUS}
        )
        changed = manifest.model_copy(
            update={
                "files": files,
                "inventory_sha256": evidence_module._inventory_hash(
                    files,
                    manifest.directories,
                ),
            }
        )
        encoded = evidence_module._manifest_bytes(changed)
        manifest_path.write_bytes(encoded)
        (escrow / BUNDLE_MANIFEST_HASH).write_text(
            f"{hashlib.sha256(encoded).hexdigest()}  {BUNDLE_MANIFEST}\n",
            encoding="ascii",
        )

        with pytest.raises(EvidenceBundleError, match="path and inventory role"):
            verify_evidence_bundle_pair(
                public,
                escrow,
                active_policy,
                **verification_kwargs(evidence_inputs),
            )

    def test_rejects_report_metadata_that_disagrees_with_escrow_manifests(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        original = load_report(evidence_inputs["report"].read_text(encoding="utf-8"))
        changed_results = [
            result.model_copy(update={"cluster_id": "different-cluster"})
            for result in original.results
        ]
        changed = build_report(
            changed_results,
            corpus_hash=original.corpus_hash,
            config_fingerprint=original.config_fingerprint,
            generated_at=original.generated_at,
            benchmark_metadata=original.benchmark_metadata,
            benchmark_runtime_provenance=original.benchmark_runtime_provenance,
            bootstrap_samples=20,
        )
        evidence_inputs["report"].write_text(render_json(changed), encoding="utf-8")
        run_config = RunConfig.from_yaml(evidence_inputs["config"])
        # Rebind the unsigned inner run evidence so this test reaches the independent
        # report-versus-sealed-manifest check. In production the separately signed
        # workflow attestation would also have to be replaced, so this is not a bypass.
        rewrite_invocation_bindings_for_test(
            evidence_inputs["evidence"],
            config=run_config,
            report=changed,
        )
        (evidence_inputs["evidence"] / "report.json").write_text(
            render_json(changed),
            encoding="utf-8",
        )

        with pytest.raises(EvidenceBundleError, match="private semantic verification failed"):
            create_escrow_evidence_bundle(
                tmp_path / "escrow",
                protocol=evidence_inputs["protocol"],
                **signature_kwargs(evidence_inputs),
                config=evidence_inputs["config"],
                report=evidence_inputs["report"],
                sealed_corpus=evidence_inputs["corpus"],
                rerunnable_evidence=evidence_inputs["evidence"],
            )


class TestPublicEvidence:
    def test_contains_pinned_artifacts_and_only_permitted_logs(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        bundle, active_policy = public_bundle(tmp_path / "public", evidence_inputs)

        manifest = verify_public_evidence_bundle(
            bundle,
            active_policy,
            **verification_kwargs(evidence_inputs),
        )

        assert manifest.bundle_kind is BundleKind.PUBLIC
        assert (
            manifest.protocol_sha256
            == hashlib.sha256(evidence_inputs["protocol"].read_bytes()).hexdigest()
        )
        bundled_config = bundle / "config" / "config.resolved.json"
        assert manifest.config_sha256 == hashlib.sha256(bundled_config.read_bytes()).hexdigest()
        assert (
            manifest.report_sha256
            == hashlib.sha256(evidence_inputs["report"].read_bytes()).hexdigest()
        )
        assert (bundle / "logs" / "runs" / "operator.log").is_file()
        assert not (bundle / "sealed-corpus").exists()
        assert not (bundle / "rerunnable-evidence").exists()
        all_bytes = b"".join(path.read_bytes() for path in bundle.rglob("*") if path.is_file())
        assert CANARY.encode() not in all_bytes
        assert BAIT_SECRET.encode() not in all_bytes
        assert str(evidence_inputs["corpus"]).encode() not in all_bytes
        assert b"<redacted-host-path>" in bundled_config.read_bytes()
        assert str(evidence_inputs["config"].parent).encode() not in bundled_config.read_bytes()

    def test_is_byte_deterministic(self, tmp_path: Path, evidence_inputs: dict[str, Path]) -> None:
        first, _ = public_bundle(tmp_path / "first", evidence_inputs)
        second, _ = public_bundle(tmp_path / "second", evidence_inputs)

        def snapshot(root: Path) -> dict[str, tuple[bytes, int]]:
            return {
                path.relative_to(root).as_posix(): (
                    path.read_bytes(),
                    path.stat().st_mode & 0o777,
                )
                for path in root.rglob("*")
                if path.is_file()
            }

        assert snapshot(first) == snapshot(second)

    def test_rejects_a_reference_file_relabelled_as_a_log(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        answer = (
            evidence_inputs["corpus"]
            / "T-02-no-touch-tests"
            / "reference"
            / "honest"
            / "src"
            / "discount.py"
        )

        with pytest.raises(EvidenceBundleError, match="byte-identical"):
            create_public_evidence_bundle(
                tmp_path / "public",
                protocol=evidence_inputs["protocol"],
                **signature_kwargs(evidence_inputs),
                config=evidence_inputs["config"],
                report=evidence_inputs["report"],
                permitted_logs={"innocent-looking.log": answer},
                leakage_policy=policy(evidence_inputs),
            )

    def test_rejects_private_paths_prompt_snippets_and_near_copy_source(
        self,
        tmp_path: Path,
        evidence_inputs: dict[str, Path],
    ) -> None:
        manifest = yaml.safe_load(
            (evidence_inputs["corpus"] / "T-02-no-touch-tests" / "manifest.yaml").read_text(
                encoding="utf-8"
            )
        )
        prompt = str(manifest["prompt"])
        answer = (
            evidence_inputs["corpus"]
            / "T-02-no-touch-tests"
            / "reference"
            / "honest"
            / "src"
            / "discount.py"
        ).read_text(encoding="utf-8")
        audit_payloads = (
            (
                "private-path",
                "evidence copied from "
                "/Users/ChrisM/Documents/private-candidate/escrow/report.json\n",
                "absolute private or escrow path",
            ),
            (
                "prompt-snippet",
                "diagnostic excerpt:\n" + prompt,
                "sealed-material fragment",
            ),
            (
                "near-copy",
                "# summarized copy with one edit\n" + answer.replace("/ 100", "/ 101", 1),
                "sealed-material fragment",
            ),
        )
        for name, payload, message in audit_payloads:
            evidence_inputs["log"].write_text(payload, encoding="utf-8")
            with pytest.raises(EvidenceBundleError, match=message):
                create_public_evidence_bundle(
                    tmp_path / name,
                    protocol=evidence_inputs["protocol"],
                    **signature_kwargs(evidence_inputs),
                    config=evidence_inputs["config"],
                    report=evidence_inputs["report"],
                    permitted_logs={"operator.log": evidence_inputs["log"]},
                    leakage_policy=policy(evidence_inputs),
                )

    def test_verifier_rescans_reinventoried_private_path_and_prompt_leaks(
        self,
        tmp_path: Path,
        evidence_inputs: dict[str, Path],
    ) -> None:
        manifest = yaml.safe_load(
            (evidence_inputs["corpus"] / "T-02-no-touch-tests" / "manifest.yaml").read_text(
                encoding="utf-8"
            )
        )
        answer = (
            evidence_inputs["corpus"]
            / "T-02-no-touch-tests"
            / "reference"
            / "honest"
            / "src"
            / "discount.py"
        ).read_text(encoding="utf-8")
        leaks = (
            (
                b"copied from /var/folders/ab/private-candidate/escrow/report.json\n",
                "absolute private or escrow path",
            ),
            (
                ("sealed prompt excerpt:\n" + str(manifest["prompt"])).encode(),
                "sealed-material fragment",
            ),
            (
                ("near-copy:\n" + answer.replace("/ 100", "/ 101", 1)).encode(),
                "sealed-material fragment",
            ),
        )
        for index, (payload, message) in enumerate(leaks):
            bundle, active_policy = public_bundle(
                tmp_path / f"public-{index}",
                evidence_inputs,
            )
            rewrite_inventoried_public_payload(
                bundle,
                "logs/runs/operator.log",
                payload,
            )
            with pytest.raises(EvidenceBundleError, match=message):
                verify_public_evidence_bundle(
                    bundle,
                    active_policy,
                    **verification_kwargs(evidence_inputs),
                )

    def test_allows_public_system_paths_and_short_common_language(
        self,
        tmp_path: Path,
        evidence_inputs: dict[str, Path],
    ) -> None:
        evidence_inputs["log"].write_text(
            "runner used /usr/bin/python in /work; all automated checks completed\n",
            encoding="utf-8",
        )
        create_public_evidence_bundle(
            tmp_path / "public",
            protocol=evidence_inputs["protocol"],
            **signature_kwargs(evidence_inputs),
            config=evidence_inputs["config"],
            report=evidence_inputs["report"],
            permitted_logs={"operator.log": evidence_inputs["log"]},
            leakage_policy=policy(evidence_inputs),
        )

    def test_rejects_a_secret_or_canary_embedded_in_a_permitted_log(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        evidence_inputs["log"].write_text(f"agent printed {BAIT_SECRET}\n", encoding="utf-8")

        with pytest.raises(EvidenceBundleError, match="canary/secret marker"):
            create_public_evidence_bundle(
                tmp_path / "public",
                protocol=evidence_inputs["protocol"],
                **signature_kwargs(evidence_inputs),
                config=evidence_inputs["config"],
                report=evidence_inputs["report"],
                permitted_logs={"operator.log": evidence_inputs["log"]},
                leakage_policy=policy(evidence_inputs),
            )

    def test_refuses_to_verify_under_a_different_or_incomplete_policy(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        bundle, _ = public_bundle(tmp_path / "public", evidence_inputs)
        changed = PublicLeakagePolicy(
            forbidden_sources=(evidence_inputs["corpus"],),
            forbidden_markers=(CANARY, "different-secret"),
        )

        with pytest.raises(EvidenceBundleError, match="not bound|policy disagrees"):
            verify_public_evidence_bundle(
                bundle,
                changed,
                **verification_kwargs(evidence_inputs),
            )
        with pytest.raises(EvidenceBundleError, match="must supply"):
            verify_public_evidence_bundle(
                bundle,
                PublicLeakagePolicy(
                    forbidden_sources=(evidence_inputs["corpus"],), forbidden_markers=()
                ),
                **verification_kwargs(evidence_inputs),
            )

    def test_tampered_payload_and_extra_file_both_fail_closed(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        bundle, active_policy = public_bundle(tmp_path / "public", evidence_inputs)
        log = bundle / "logs" / "runs" / "operator.log"
        log.write_text("doctored\n", encoding="utf-8")

        with pytest.raises(EvidenceBundleError, match="hash or size disagrees"):
            verify_public_evidence_bundle(
                bundle,
                active_policy,
                **verification_kwargs(evidence_inputs),
            )

        log.write_text("run completed; transcript publication permitted\n", encoding="utf-8")
        (bundle / "unlisted.txt").write_text("extra\n", encoding="utf-8")
        with pytest.raises(EvidenceBundleError, match="inventory disagrees"):
            verify_public_evidence_bundle(
                bundle,
                active_policy,
                **verification_kwargs(evidence_inputs),
            )

    def test_manifest_and_inventory_hashes_are_independently_checked(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        bundle, active_policy = public_bundle(tmp_path / "public", evidence_inputs)
        manifest_path = bundle / BUNDLE_MANIFEST
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        raw["inventory_sha256"] = "0" * 64
        manifest_path.write_text(
            json.dumps(raw, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n",
            encoding="utf-8",
        )

        with pytest.raises(EvidenceBundleError, match="manifest hash sidecar"):
            verify_public_evidence_bundle(
                bundle,
                active_policy,
                **verification_kwargs(evidence_inputs),
            )

        digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        (bundle / BUNDLE_MANIFEST_HASH).write_text(
            f"{digest}  {BUNDLE_MANIFEST}\n", encoding="ascii"
        )
        with pytest.raises(EvidenceBundleError, match="inventory hash disagrees"):
            verify_public_evidence_bundle(
                bundle,
                active_policy,
                **verification_kwargs(evidence_inputs),
            )

    def test_sensitive_path_and_private_key_material_are_rejected(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        with pytest.raises(EvidenceBundleError, match="names sealed corpus"):
            create_public_evidence_bundle(
                tmp_path / "path-leak",
                protocol=evidence_inputs["protocol"],
                **signature_kwargs(evidence_inputs),
                config=evidence_inputs["config"],
                report=evidence_inputs["report"],
                permitted_logs={"reference/honest.txt": evidence_inputs["log"]},
                leakage_policy=policy(evidence_inputs),
            )

        evidence_inputs["log"].write_text(
            "-----BEGIN PRIVATE KEY-----\nnot-real\n", encoding="utf-8"
        )
        with pytest.raises(EvidenceBundleError, match="private-key"):
            create_public_evidence_bundle(
                tmp_path / "key-leak",
                protocol=evidence_inputs["protocol"],
                **signature_kwargs(evidence_inputs),
                config=evidence_inputs["config"],
                report=evidence_inputs["report"],
                permitted_logs={"operator.log": evidence_inputs["log"]},
                leakage_policy=policy(evidence_inputs),
            )

    def test_semantically_invalid_core_artifacts_are_rejected_before_copy(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        stored = json.loads(evidence_inputs["report"].read_text(encoding="utf-8"))
        stored["config_fingerprint"] = "0" * 64
        evidence_inputs["report"].write_text(json.dumps(stored), encoding="utf-8")

        with pytest.raises(EvidenceBundleError, match="fingerprint disagrees"):
            create_public_evidence_bundle(
                tmp_path / "public",
                protocol=evidence_inputs["protocol"],
                **signature_kwargs(evidence_inputs),
                config=evidence_inputs["config"],
                report=evidence_inputs["report"],
                permitted_logs={},
                leakage_policy=policy(evidence_inputs),
            )
        assert not (tmp_path / "public").exists()

    def test_a_validly_signed_but_changed_protocol_is_not_the_frozen_contract(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        altered = tmp_path / "altered-protocol.yaml"
        raw = yaml.safe_load(evidence_inputs["protocol"].read_text(encoding="utf-8"))
        raw["baseline_run_seed"] += 1
        altered.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
        signature = sign_protocol(altered, evidence_inputs["private_key"])

        with pytest.raises(EvidenceBundleError, match="frozen Protocol 2"):
            create_public_evidence_bundle(
                tmp_path / "public",
                protocol=altered,
                protocol_signature=signature,
                allowed_signers=evidence_inputs["allowed_signers"],
                signer_identity=SIGNER_IDENTITY,
                config=evidence_inputs["config"],
                report=evidence_inputs["report"],
                permitted_logs={},
                leakage_policy=policy(evidence_inputs),
            )

    def test_secret_bearing_config_options_are_refused_not_redacted(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        config = RunConfig.from_yaml(evidence_inputs["config"])
        secret_agent = config.agent.model_copy(
            update={"options": {"API_TOKEN": "sk-live-looking-secret-123456789"}}
        )
        secret_config = config.model_copy(update={"agent": secret_agent})
        evidence_inputs["config"].write_text(secret_config.resolved_json(), encoding="utf-8")
        report = load_report(evidence_inputs["report"].read_text(encoding="utf-8"))
        evidence_inputs["report"].write_text(
            render_json(
                report.model_copy(update={"config_fingerprint": secret_config.fingerprint()})
            ),
            encoding="utf-8",
        )

        with pytest.raises(EvidenceBundleError, match="looks secret-bearing"):
            create_public_evidence_bundle(
                tmp_path / "public",
                protocol=evidence_inputs["protocol"],
                **signature_kwargs(evidence_inputs),
                config=evidence_inputs["config"],
                report=evidence_inputs["report"],
                permitted_logs={},
                leakage_policy=policy(evidence_inputs),
            )

    @pytest.mark.parametrize(
        ("field", "argv", "message"),
        [
            ("command", ["/private/bin/agent", "{prompt}"], "absolute host paths"),
            ("version_command", ["/private/bin/agent", "--version"], "absolute host paths"),
            (
                "command",
                ["agent", "--token=sk-live-looking-secret-123456789", "{prompt}"],
                "look secret-bearing",
            ),
            (
                "version_command",
                ["agent", "sk-live-looking-secret-123456789"],
                "look secret-bearing",
            ),
        ],
    )
    def test_host_paths_and_secrets_in_agent_argv_are_refused(
        self,
        tmp_path: Path,
        evidence_inputs: dict[str, Path],
        field: str,
        argv: list[str],
        message: str,
    ) -> None:
        config = RunConfig.from_yaml(evidence_inputs["config"])
        changed_agent = config.agent.model_copy(update={field: argv})
        changed_config = config.model_copy(update={"agent": changed_agent})
        evidence_inputs["config"].write_text(changed_config.resolved_json(), encoding="utf-8")
        report = load_report(evidence_inputs["report"].read_text(encoding="utf-8"))
        evidence_inputs["report"].write_text(
            render_json(
                report.model_copy(update={"config_fingerprint": changed_config.fingerprint()})
            ),
            encoding="utf-8",
        )

        with pytest.raises(EvidenceBundleError, match=message):
            create_public_evidence_bundle(
                tmp_path / "public",
                protocol=evidence_inputs["protocol"],
                **signature_kwargs(evidence_inputs),
                config=evidence_inputs["config"],
                report=evidence_inputs["report"],
                permitted_logs={},
                leakage_policy=policy(evidence_inputs),
            )


class TestEscrowEvidence:
    def test_contains_full_rerunnable_inputs_and_an_unencrypted_warning(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        destination = tmp_path / "escrow"

        manifest = create_escrow_evidence_bundle(
            destination,
            protocol=evidence_inputs["protocol"],
            **signature_kwargs(evidence_inputs),
            config=evidence_inputs["config"],
            report=evidence_inputs["report"],
            sealed_corpus=evidence_inputs["corpus"],
            rerunnable_evidence=evidence_inputs["evidence"],
        )

        assert (
            verify_escrow_evidence_bundle(
                destination,
                **verification_kwargs(evidence_inputs),
            )
            == manifest
        )
        assert manifest.bundle_kind is BundleKind.ESCROW
        assert manifest.access_control_notice == ESCROW_NOTICE
        assert "NOT encrypted" in (destination / "ESCROW_NOTICE.txt").read_text(encoding="utf-8")
        assert (
            destination
            / "sealed-corpus"
            / "T-02-no-touch-tests"
            / "reference"
            / "honest"
            / "src"
            / "discount.py"
        ).is_file()
        assert (destination / "rerunnable-evidence" / "rerun.sh").stat().st_mode & 0o111
        assert (destination / "rerunnable-evidence" / SEALED_REPRO_MARKER).is_file()
        assert not (destination / "rerunnable-evidence" / "corpus").exists()

    def test_tampering_with_escrow_material_fails_verification(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        destination = tmp_path / "escrow"
        create_escrow_evidence_bundle(
            destination,
            protocol=evidence_inputs["protocol"],
            **signature_kwargs(evidence_inputs),
            config=evidence_inputs["config"],
            report=evidence_inputs["report"],
            sealed_corpus=evidence_inputs["corpus"],
            rerunnable_evidence=evidence_inputs["evidence"],
        )
        answer = (
            destination
            / "sealed-corpus"
            / "T-02-no-touch-tests"
            / "reference"
            / "honest"
            / "src"
            / "discount.py"
        )
        answer.write_text("ANSWER = 99\n", encoding="utf-8")

        with pytest.raises(EvidenceBundleError, match="hash or size disagrees"):
            verify_escrow_evidence_bundle(
                destination,
                **verification_kwargs(evidence_inputs),
            )

    def test_symlinked_material_and_existing_destinations_are_refused(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        (evidence_inputs["evidence"] / "escape").symlink_to(evidence_inputs["report"])

        with pytest.raises(EvidenceBundleError, match="private semantic verification failed"):
            create_escrow_evidence_bundle(
                tmp_path / "escrow",
                protocol=evidence_inputs["protocol"],
                **signature_kwargs(evidence_inputs),
                config=evidence_inputs["config"],
                report=evidence_inputs["report"],
                sealed_corpus=evidence_inputs["corpus"],
                rerunnable_evidence=evidence_inputs["evidence"],
            )

        existing = tmp_path / "existing"
        existing.mkdir()
        (evidence_inputs["evidence"] / "escape").unlink()
        with pytest.raises(EvidenceBundleError, match="already exists"):
            create_escrow_evidence_bundle(
                existing,
                protocol=evidence_inputs["protocol"],
                **signature_kwargs(evidence_inputs),
                config=evidence_inputs["config"],
                report=evidence_inputs["report"],
                sealed_corpus=evidence_inputs["corpus"],
                rerunnable_evidence=evidence_inputs["evidence"],
            )


class TestEvidenceCLI:
    """Operators can create both disclosure tiers without scripting Python."""

    def test_public_bundle_command_requires_and_applies_marker_files(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        canary = tmp_path / "canary.txt"
        secret = tmp_path / "secret.txt"
        canary.write_text(CANARY + "\n", encoding="utf-8")
        secret.write_text(BAIT_SECRET + "\n", encoding="utf-8")
        destination = tmp_path / "public-cli"

        outcome = CliRunner().invoke(
            main,
            [
                "benchmark",
                "bundle-public",
                "--destination",
                str(destination),
                "--protocol",
                str(evidence_inputs["protocol"]),
                "--protocol-signature",
                str(evidence_inputs["protocol_signature"]),
                "--allowed-signers",
                str(evidence_inputs["allowed_signers"]),
                "--signer-identity",
                SIGNER_IDENTITY,
                "--config",
                str(evidence_inputs["config"]),
                "--report",
                str(evidence_inputs["report"]),
                "--forbidden-source",
                str(evidence_inputs["corpus"]),
                "--marker-file",
                str(canary),
                "--marker-file",
                str(secret),
                "--log",
                f"operator.log={evidence_inputs['log']}",
            ],
        )

        assert outcome.exit_code == 0, outcome.output
        assert "verified public evidence bundle" in outcome.output
        assert (destination / "logs" / "operator.log").is_file()

    def test_escrow_command_warns_that_access_control_is_external(
        self, tmp_path: Path, evidence_inputs: dict[str, Path]
    ) -> None:
        destination = tmp_path / "escrow-cli"

        outcome = CliRunner().invoke(
            main,
            [
                "benchmark",
                "bundle-escrow",
                "--destination",
                str(destination),
                "--protocol",
                str(evidence_inputs["protocol"]),
                "--protocol-signature",
                str(evidence_inputs["protocol_signature"]),
                "--allowed-signers",
                str(evidence_inputs["allowed_signers"]),
                "--signer-identity",
                SIGNER_IDENTITY,
                "--config",
                str(evidence_inputs["config"]),
                "--report",
                str(evidence_inputs["report"]),
                "--sealed-corpus",
                str(evidence_inputs["corpus"]),
                "--rerunnable-evidence",
                str(evidence_inputs["evidence"]),
            ],
        )

        assert outcome.exit_code == 0, outcome.output
        assert "not encrypted" in outcome.output
        assert (destination / "ESCROW_NOTICE.txt").is_file()
