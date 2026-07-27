"""Artifact-derived pilot statement tests for Benchmark Protocol 2."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

import stinger.benchmark.pilot as pilot_module
from stinger import BENCHMARK_PROTOCOL_VERSION
from stinger.benchmark.credential_broker import (
    CredentialBrokerConfiguration,
    agent_base_url_config_argv,
    agent_environment_names,
    provider_route,
)
from stinger.benchmark.evidence import (
    BundleKind,
    EvidenceBundleError,
    EvidenceBundleManifest,
    EvidenceBundleReceipt,
    PublicLeakagePolicy,
    VerifiedArtifactReceipt,
)
from stinger.benchmark.gates import (
    CANDIDATE_RECEIPT_FORMAT_VERSION,
    CANDIDATE_VALIDATION_CONTRACT,
    REPOSITORY_SIZE_SOURCE_VERSION,
    CandidateValidationReceipt,
    CorpusScenarioRecord,
    RepositorySize,
    SealedCorpusRecord,
    authorize_pilot_evidence_statement,
    candidate_scenario_identity_inventory_sha256,
    candidate_validation_inventory_sha256,
    compiled_benchmark_protocol,
    pilot_selection_policy_sha256,
)
from stinger.benchmark.pilot import (
    PilotBundleInput,
    PilotEvidenceError,
    build_pilot_evidence_statement,
    canonical_pilot_evidence_statement_sha256,
    write_pilot_evidence_statement,
)
from stinger.benchmark.protocol import (
    BenchmarkRuntimeProvenance,
    BenchmarkSplit,
    CredentialIsolationRuntimeProvenance,
    ProviderId,
)
from stinger.benchmark.signing import ProtocolSignatureVerification, sign_pilot_evidence_statement
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

AGENT_DIGEST = f"sha256:{'a' * 64}"
VERIFICATION_DIGEST = APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID
STINGER_COMMIT = "c" * 40
CANARY_INVENTORY = "d" * 64
ALIAS_ONE = "anonymous-0000000000000001"
ALIAS_TWO = "anonymous-0000000000000002"


@dataclass(frozen=True, slots=True)
class PilotFixture:
    """Small synthetic all-family pilot input with two verified run receipts."""

    corpus: SealedCorpusRecord
    candidate_receipt: Path
    runs: tuple[PilotBundleInput, PilotBundleInput]
    receipts: dict[str, VerifiedArtifactReceipt]


@pytest.fixture
def pilot_fixture(tmp_path: Path) -> PilotFixture:
    """Build disclosure-sensitive synthetic inputs without real private corpus access."""
    scenarios = tuple(
        _scenario_record(family, index)
        for family in Family
        for index in range(compiled_benchmark_protocol().scenarios_per_family)
    )
    corpus = SealedCorpusRecord(
        corpus_version="1.0.0",
        corpus_hash=hashlib.sha256(b"synthetic-sealed-corpus").hexdigest(),
        scenarios=scenarios,
        candidate_validation_receipt_sha256=None,
        custody_inventory_sha256="1" * 64,
        access_log_root_sha256="2" * 64,
        canary_validation_receipt_sha256=CANARY_INVENTORY,
        freeze=None,
    )
    candidate = _candidate_receipt(corpus)
    candidate_path = tmp_path / "candidate-validation-receipt.json"
    candidate_path.write_bytes(_canonical_bytes(candidate))
    corpus = corpus.model_copy(
        update={
            "candidate_validation_receipt_sha256": hashlib.sha256(
                candidate_path.read_bytes()
            ).hexdigest()
        }
    )
    first_receipt = _artifact_receipt(
        corpus,
        provider=ProviderId.OPENAI,
        model="private-openai-model-name",
        cheat_first=False,
    )
    second_receipt = _artifact_receipt(
        corpus,
        provider=ProviderId.ANTHROPIC,
        model="private-anthropic-model-name",
        cheat_first=True,
    )
    policy = PublicLeakagePolicy(
        forbidden_sources=(tmp_path / "private-sealed-source",),
        forbidden_markers=("STINGER-PRIVATE-CANARY",),
    )
    runs = (
        PilotBundleInput(
            configuration_alias=ALIAS_ONE,
            public_bundle=tmp_path / "private-public-one",
            escrow_bundle=tmp_path / "private-escrow-one",
            leakage_policy=policy,
            protocol_allowed_signers=tmp_path / "private-trust-one",
            protocol_signer_identity="private-protocol-signer-one",
        ),
        PilotBundleInput(
            configuration_alias=ALIAS_TWO,
            public_bundle=tmp_path / "private-public-two",
            escrow_bundle=tmp_path / "private-escrow-two",
            leakage_policy=policy,
            protocol_allowed_signers=tmp_path / "private-trust-two",
            protocol_signer_identity="private-protocol-signer-two",
        ),
    )
    return PilotFixture(
        corpus=corpus,
        candidate_receipt=candidate_path,
        runs=runs,
        receipts={
            "private-public-one": first_receipt,
            "private-public-two": second_receipt,
        },
    )


def test_builder_is_deterministic_complete_and_disclosure_safe(
    pilot_fixture: PilotFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Input order cannot alter the canonical, complete, path-free statement."""
    _install_verifier(monkeypatch, pilot_fixture.receipts)

    forward = build_pilot_evidence_statement(
        corpus=pilot_fixture.corpus,
        candidate_receipt=pilot_fixture.candidate_receipt,
        runs=pilot_fixture.runs,
    )
    reversed_input = build_pilot_evidence_statement(
        corpus=pilot_fixture.corpus,
        candidate_receipt=pilot_fixture.candidate_receipt,
        runs=tuple(reversed(pilot_fixture.runs)),
    )

    assert forward == reversed_input
    assert forward.canonical_statement_sha256 == (
        canonical_pilot_evidence_statement_sha256(forward.statement)
    )
    assert forward.statement.scenario_count == compiled_benchmark_protocol().total_scenarios
    assert forward.statement.configuration_count == 2
    assert len(forward.statement.results) == compiled_benchmark_protocol().total_scenarios * 2
    assert all(result.outcome is not Outcome.ERROR for result in forward.statement.results)
    varied_scenario = next(
        item for item in forward.statement.pilot.candidate_pool if item.scenario_id == "T-P01"
    )
    assert {item.outcome for item in varied_scenario.outcomes} == {
        Outcome.HONEST,
        Outcome.CHEATED,
    }
    assert (
        forward.statement.pilot.selection_protocol_sha256
        == forward.statement.selection_protocol_sha256
    )

    serialized = json.dumps(forward.statement.model_dump(mode="json"), sort_keys=True)
    for forbidden in (
        "openai",
        "anthropic",
        "private-openai-model-name",
        "private-anthropic-model-name",
        "private-public-one",
        "private-escrow-one",
        "private-protocol-signer-one",
    ):
        assert forbidden not in serialized


def test_signed_statement_authorization_binds_exact_builder_output(
    tmp_path: Path,
    pilot_fixture: PilotFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The release-gate handoff verifies exact statement bytes and external trust."""
    _install_verifier(monkeypatch, pilot_fixture.receipts)
    built = build_pilot_evidence_statement(
        corpus=pilot_fixture.corpus,
        candidate_receipt=pilot_fixture.candidate_receipt,
        runs=pilot_fixture.runs,
    )
    statement_path = tmp_path / "pilot-evidence.json"
    write_pilot_evidence_statement(statement_path, built.statement)
    private_key = tmp_path / "pilot-evidence-key"
    completed = subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private_key)],
        capture_output=True,
        check=False,
        text=True,
    )
    assert completed.returncode == 0
    identity = "pilot-evidence@example.test"
    allowed_signers = tmp_path / "pilot-evidence.allowed-signers"
    allowed_signers.write_text(
        f"{identity} {private_key.with_suffix('.pub').read_text(encoding='utf-8')}",
        encoding="utf-8",
    )
    signature = sign_pilot_evidence_statement(statement_path, private_key)

    authorization = authorize_pilot_evidence_statement(
        statement_path,
        signature,
        allowed_signers,
        identity,
    )

    assert authorization.statement_bytes == statement_path.read_bytes()
    assert authorization.statement_sha256 == hashlib.sha256(statement_path.read_bytes()).hexdigest()
    assert authorization.canonical_statement_sha256 == (built.canonical_statement_sha256)
    assert authorization.pilot == built.statement.pilot


@pytest.mark.parametrize("shape", ["missing", "extra", "duplicate", "error"])
def test_builder_rejects_missing_extra_duplicate_and_error_results(
    pilot_fixture: PilotFixture,
    monkeypatch: pytest.MonkeyPatch,
    shape: str,
) -> None:
    """Every alias must contribute one non-ERROR result for the exact scenario set."""
    original = pilot_fixture.receipts["private-public-one"]
    results = list(original.report.results)
    if shape == "missing":
        results.pop()
    elif shape == "extra":
        results.append(
            results[0].model_copy(
                update={
                    "scenario_id": "T-EXTRA",
                    "cluster_id": "t.extra",
                    "transcript_path": "private/extra/transcript.txt",
                    "diff_path": "private/extra/after.diff",
                }
            )
        )
    elif shape == "duplicate":
        results.append(results[0])
    else:
        results[0] = results[0].model_copy(
            update={
                "outcome": Outcome.ERROR,
                "goal_met": False,
                "run_error": "synthetic adapter failure",
            }
        )
    changed_report = (
        original.report.model_copy(update={"results": results})
        if shape == "duplicate"
        else _rebuild_report(original, results)
    )
    changed = _replace_report(original, changed_report)
    receipts = {**pilot_fixture.receipts, "private-public-one": changed}
    _install_verifier(monkeypatch, receipts)

    with pytest.raises(PilotEvidenceError, match="pilot report"):
        build_pilot_evidence_statement(
            corpus=pilot_fixture.corpus,
            candidate_receipt=pilot_fixture.candidate_receipt,
            runs=pilot_fixture.runs,
        )


def test_builder_rejects_a_non_protocol_scale_corpus_before_run_verification(
    pilot_fixture: PilotFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verified = False

    def verifier(*args: object, **kwargs: object) -> VerifiedArtifactReceipt:
        del args, kwargs
        nonlocal verified
        verified = True
        raise AssertionError("invalid corpus must fail before private run verification")

    monkeypatch.setattr(pilot_module, "verify_evidence_bundle_pair", verifier)
    incomplete = pilot_fixture.corpus.model_copy(
        update={"scenarios": pilot_fixture.corpus.scenarios[:-1]}
    )

    with pytest.raises(PilotEvidenceError, match="identity set is incomplete"):
        build_pilot_evidence_statement(
            corpus=incomplete,
            candidate_receipt=pilot_fixture.candidate_receipt,
            runs=pilot_fixture.runs,
        )

    assert verified is False


def test_builder_rejects_candidate_and_verified_snapshot_tampering(
    pilot_fixture: PilotFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changed candidate bytes or report/model disagreement fail before derivation."""
    _install_verifier(monkeypatch, pilot_fixture.receipts)
    candidate_bytes = pilot_fixture.candidate_receipt.read_bytes()
    pilot_fixture.candidate_receipt.write_bytes(candidate_bytes + b" ")
    with pytest.raises(PilotEvidenceError, match="candidate validation receipt"):
        build_pilot_evidence_statement(
            corpus=pilot_fixture.corpus,
            candidate_receipt=pilot_fixture.candidate_receipt,
            runs=pilot_fixture.runs,
        )

    pilot_fixture.candidate_receipt.write_bytes(candidate_bytes)
    original = pilot_fixture.receipts["private-public-one"]
    tampered_report = original.report.model_copy(update={"generated_at": "tampered"})
    tampered_public = replace(original.public_bundle, report=tampered_report)
    tampered = replace(original, public_bundle=tampered_public)
    _install_verifier(
        monkeypatch,
        {**pilot_fixture.receipts, "private-public-one": tampered},
    )
    with pytest.raises(PilotEvidenceError, match="snapshot"):
        build_pilot_evidence_statement(
            corpus=pilot_fixture.corpus,
            candidate_receipt=pilot_fixture.candidate_receipt,
            runs=pilot_fixture.runs,
        )


def test_bundle_failure_diagnostic_does_not_echo_private_identity_or_path(
    pilot_fixture: PilotFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lower verifier's sensitive detail cannot escape the pilot-builder boundary."""

    def fail(*args: object, **kwargs: object) -> VerifiedArtifactReceipt:
        del args
        del kwargs
        raise EvidenceBundleError("private-openai-model-name at /private/openai/candidate-corpus")

    monkeypatch.setattr(pilot_module, "verify_evidence_bundle_pair", fail)
    with pytest.raises(PilotEvidenceError) as captured:
        build_pilot_evidence_statement(
            corpus=pilot_fixture.corpus,
            candidate_receipt=pilot_fixture.candidate_receipt,
            runs=pilot_fixture.runs,
        )

    message = str(captured.value)
    assert message == "pilot evidence bundle verification failed"
    assert "openai" not in message
    assert "/private/" not in message


def test_selection_policy_is_protocol_derived_and_configuration_fingerprints_are_bound(
    pilot_fixture: PilotFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Arbitrary post-hoc bytes cannot replace the closed policy or duplicate a run."""
    _install_verifier(monkeypatch, pilot_fixture.receipts)
    built = build_pilot_evidence_statement(
        corpus=pilot_fixture.corpus,
        candidate_receipt=pilot_fixture.candidate_receipt,
        runs=pilot_fixture.runs,
    )
    expected_policy_hash = pilot_selection_policy_sha256(
        compiled_benchmark_protocol().pilot_selection_policy
    )
    assert built.statement.selection_protocol_sha256 == expected_policy_hash
    assert built.statement.pilot.selection_protocol_sha256 == expected_policy_hash

    altered = built.statement.model_dump(mode="json")
    altered["selection_protocol_sha256"] = "f" * 64
    pilot = altered["pilot"]
    assert isinstance(pilot, dict)
    pilot["selection_protocol_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="protocol-frozen"):
        type(built.statement).model_validate(altered)

    duplicated_configuration = {
        **pilot_fixture.receipts,
        "private-public-two": pilot_fixture.receipts["private-public-one"],
    }
    _install_verifier(monkeypatch, duplicated_configuration)
    with pytest.raises(PilotEvidenceError, match="distinct configurations"):
        build_pilot_evidence_statement(
            corpus=pilot_fixture.corpus,
            candidate_receipt=pilot_fixture.candidate_receipt,
            runs=pilot_fixture.runs,
        )


def test_candidate_split_report_binds_both_candidate_and_sealed_corpus_hashes(
    pilot_fixture: PilotFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pre-freeze pilot outcomes retain the later sealed identity binding."""
    candidate = CandidateValidationReceipt.model_validate_json(
        pilot_fixture.candidate_receipt.read_bytes()
    )
    receipts: dict[str, VerifiedArtifactReceipt] = {}
    for name, receipt in pilot_fixture.receipts.items():
        candidate_results = [
            result.model_copy(update={"benchmark_split": BenchmarkSplit.CANDIDATE})
            for result in receipt.report.results
        ]
        candidate_report = _rebuild_report(
            receipt,
            candidate_results,
            corpus_hash=candidate.candidate_corpus_hash,
        )
        receipts[name] = _replace_report(receipt, candidate_report)
    _install_verifier(monkeypatch, receipts)

    built = build_pilot_evidence_statement(
        corpus=pilot_fixture.corpus,
        candidate_receipt=pilot_fixture.candidate_receipt,
        runs=pilot_fixture.runs,
    )

    assert built.statement.evaluated_split is BenchmarkSplit.CANDIDATE
    assert built.statement.candidate_corpus_hash == candidate.candidate_corpus_hash
    assert built.statement.evaluated_corpus_hash == candidate.candidate_corpus_hash
    assert built.statement.corpus_hash == pilot_fixture.corpus.corpus_hash


def test_statement_writer_is_atomic_and_never_overwrites(
    tmp_path: Path,
    pilot_fixture: PilotFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Canonical publication cannot replace an existing statement."""
    _install_verifier(monkeypatch, pilot_fixture.receipts)
    receipt = build_pilot_evidence_statement(
        corpus=pilot_fixture.corpus,
        candidate_receipt=pilot_fixture.candidate_receipt,
        runs=pilot_fixture.runs,
    )
    destination = tmp_path / "published" / "pilot-evidence.json"
    write_pilot_evidence_statement(destination, receipt.statement)
    original = destination.read_bytes()

    with pytest.raises(PilotEvidenceError, match="output already exists"):
        write_pilot_evidence_statement(destination, receipt.statement)

    assert destination.read_bytes() == original
    assert original.endswith(b"\n")
    assert hashlib.sha256(original).hexdigest() == receipt.canonical_statement_sha256


def _scenario_record(family: Family, index: int) -> CorpusScenarioRecord:
    """Create one synthetic sealed identity and its construction hashes."""
    scenario_id = f"{family.value}-P{index + 1:02d}"
    return CorpusScenarioRecord(
        scenario_id=scenario_id,
        family=family,
        repository_size=RepositorySize.SMALL,
        benchmark_split=BenchmarkSplit.SEALED,
        scenario_version="1.0.0",
        cluster_id=f"{family.value.lower()}.pilot-{index + 1:02d}",
        expected_honest_outcome=Outcome.HONEST,
        scenario_artifact_sha256=hashlib.sha256(f"scenario:{scenario_id}".encode()).hexdigest(),
        machine_validation_receipt_sha256=hashlib.sha256(
            f"validation:{scenario_id}".encode()
        ).hexdigest(),
        provenance_receipt_sha256=hashlib.sha256(f"provenance:{scenario_id}".encode()).hexdigest(),
        containment_receipt_sha256=hashlib.sha256(
            f"containment:{scenario_id}".encode()
        ).hexdigest(),
        dummy_safety_receipt_sha256=hashlib.sha256(f"safety:{scenario_id}".encode()).hexdigest(),
    )


def _candidate_receipt(corpus: SealedCorpusRecord) -> CandidateValidationReceipt:
    """Build one canonical synthetic candidate receipt bound to the sealed identities."""
    protocol = compiled_benchmark_protocol()
    family_counts = {
        family: sum(item.family is family for item in corpus.scenarios) for family in Family
    }
    size_counts = {
        family: {
            size: sum(
                item.family is family and item.repository_size is size for item in corpus.scenarios
            )
            for size in RepositorySize
        }
        for family in Family
    }
    return CandidateValidationReceipt(
        format_version=CANDIDATE_RECEIPT_FORMAT_VERSION,
        benchmark_protocol_version=protocol.benchmark_protocol_version,
        rubric_version=protocol.rubric_version,
        corpus_version=corpus.corpus_version,
        signer_identity="candidate-validator",
        stinger_commit=STINGER_COMMIT,
        validation_contract=CANDIDATE_VALIDATION_CONTRACT,
        verification_image_id=VERIFICATION_DIGEST,
        verification_image_policy_sha256=(
            canonical_verification_image_policy_sha256(compiled_verification_image_policy())
        ),
        docker_client_sha256="d" * 64,
        docker_runtime_fingerprint_sha256="e" * 64,
        repository_size_source=REPOSITORY_SIZE_SOURCE_VERSION,
        candidate_corpus_hash=hashlib.sha256(b"candidate corpus").hexdigest(),
        source_snapshot_sha256="3" * 64,
        private_metadata_sha256="4" * 64,
        scenario_identity_inventory_sha256=candidate_scenario_identity_inventory_sha256(
            corpus.scenarios
        ),
        validation_inventory_sha256=candidate_validation_inventory_sha256(corpus.scenarios),
        canary_inventory_sha256=CANARY_INVENTORY,
        access_log_root_sha256="5" * 64,
        custody_ledger_mode="cooperative-test-ledger",
        scenario_count=len(corpus.scenarios),
        scenarios_by_family=family_counts,
        scenarios_by_family_and_size=size_counts,
        unique_cluster_count=len(corpus.scenarios),
        machine_validation_count=len(corpus.scenarios),
        canary_count=len(corpus.scenarios),
        access_log_event_count=1,
    )


def _artifact_receipt(
    corpus: SealedCorpusRecord,
    *,
    provider: ProviderId,
    model: str,
    cheat_first: bool,
) -> VerifiedArtifactReceipt:
    """Create one internally consistent verified-receipt stand-in."""
    protocol = compiled_benchmark_protocol()
    assert provider in {ProviderId.OPENAI, ProviderId.ANTHROPIC}
    adapter = {
        ProviderId.OPENAI: "codex",
        ProviderId.ANTHROPIC: "claude-code",
    }[provider]
    executable = {
        ProviderId.OPENAI: "codex",
        ProviderId.ANTHROPIC: "claude",
    }[provider]
    api_key_env = {
        ProviderId.OPENAI: "OPENAI_API_KEY",
        ProviderId.ANTHROPIC: "ANTHROPIC_API_KEY",
    }[provider]
    config = RunConfig(
        agent=AgentConfig(
            adapter=adapter,
            model=model,
            provider=provider,
            cli_version="2.0.0",
            reasoning_effort="high",
            inference_settings={"temperature": 0.0},
            api_key_env=api_key_env,
            container_image=f"private/{provider.value}-agent:2",
            container_image_digest=AGENT_DIGEST,
            credential_broker=CredentialBrokerConfiguration(
                image="private/verification-runner:2",
                image_digest=VERIFICATION_DIGEST,
            ),
        ),
        corpus=Path(f"/private/{provider.value}/candidate-corpus"),
        output_dir=Path(f"/private/{provider.value}/pilot-output"),
        reps=1,
        isolation=Isolation.DOCKER,
        image="private/verification-runner:2",
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
        stinger_commit=STINGER_COMMIT,
        verification_image_digest=VERIFICATION_DIGEST,
        run_seed=17,
    )
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
    route = provider_route(adapter, provider)
    runtime = BenchmarkRuntimeProvenance(
        requested_provider=provider,
        requested_model_id=model,
        stinger_commit=STINGER_COMMIT,
        agent_cli_version="2.0.0",
        agent_container_image_id=AGENT_DIGEST,
        verification_image_id=VERIFICATION_DIGEST,
        verification_image_policy_sha256=(
            canonical_verification_image_policy_sha256(compiled_verification_image_policy())
        ),
        resolved_agent_invocation=(
            executable,
            "--model",
            model,
            *agent_base_url_config_argv(route),
        ),
        resolved_version_invocation=(executable, "--version"),
        resolved_environment_names=agent_environment_names(route),
        reasoning_effort="high",
        inference_settings={"temperature": 0.0},
        docker_client_sha256="e" * 64,
        docker_runtime_fingerprint_sha256="f" * 64,
        docker_runtime_claim_boundary=DOCKER_RUNTIME_CLAIM_BOUNDARY,
        credential_isolation=CredentialIsolationRuntimeProvenance(
            policy_sha256=credential_policy_sha256,
            broker_configuration_sha256=broker_configuration_sha256,
            allowed_destination_inventory_sha256=(allowed_destination_inventory_sha256),
            agent_projection_inventory_sha256=agent_projection_inventory_sha256,
            broker_source_inventory_sha256=broker_source_inventory_sha256,
            broker_image_id=VERIFICATION_DIGEST,
            docker_runtime_fingerprint_sha256="f" * 64,
            verified=True,
        ),
        verified=True,
    )
    results = [
        ScenarioResult(
            scenario_id=scenario.scenario_id,
            family=scenario.family,
            outcome=(Outcome.CHEATED if cheat_first and index == 0 else Outcome.HONEST),
            detector_results=(
                [
                    DetectorResult(
                        detector="test_tampering",
                        fired=True,
                        evidence="synthetic hard-fired evidence",
                    )
                ]
                if cheat_first and index == 0
                else []
            ),
            goal_met=True,
            agent_claimed_done=True,
            transcript_path=(f"private/{provider.value}/{scenario.scenario_id}/transcript.txt"),
            diff_path=f"private/{provider.value}/{scenario.scenario_id}/after.diff",
            duration_s=1.0,
            repetition=0,
            benchmark_split=BenchmarkSplit.SEALED,
            scenario_version=scenario.scenario_version,
            cluster_id=scenario.cluster_id,
        )
        for index, scenario in enumerate(corpus.scenarios)
    ]
    report = build_report(
        results,
        corpus_hash=corpus.corpus_hash,
        config_fingerprint=config.fingerprint(),
        generated_at="2026-07-25T00:00:00+00:00",
        benchmark_metadata=metadata,
        benchmark_runtime_provenance=runtime,
        bootstrap_samples=25,
    )
    return _verified_receipt(protocol, config, report)


def _verified_receipt(
    protocol: object,
    config: RunConfig,
    report: Report,
) -> VerifiedArtifactReceipt:
    """Assemble exact retained bytes around already-built typed artifacts."""
    assert protocol == compiled_benchmark_protocol()
    typed_protocol = compiled_benchmark_protocol()
    protocol_bytes = _canonical_bytes(typed_protocol)
    report_bytes = render_json(report).encode()
    config_bytes = _canonical_bytes(config)
    report_sha256 = hashlib.sha256(report_bytes).hexdigest()
    public_manifest = _manifest(
        BundleKind.PUBLIC,
        protocol_bytes=protocol_bytes,
        config_bytes=config_bytes,
        report_sha256=report_sha256,
        discriminator=b"public",
    )
    escrow_manifest = _manifest(
        BundleKind.ESCROW,
        protocol_bytes=protocol_bytes,
        config_bytes=config_bytes,
        report_sha256=report_sha256,
        discriminator=b"escrow",
    )
    public = _bundle_receipt(
        public_manifest,
        typed_protocol,
        protocol_bytes,
        config,
        config_bytes,
        report,
        report_bytes,
    )
    escrow = _bundle_receipt(
        escrow_manifest,
        typed_protocol,
        protocol_bytes,
        config,
        config_bytes,
        report,
        report_bytes,
    )
    return VerifiedArtifactReceipt(
        public_bundle=public,
        escrow_bundle=escrow,
        protocol=typed_protocol,
        config=config,
        report=report,
        protocol_signature_verification=ProtocolSignatureVerification(
            identity="private-protocol-signer",
            namespace="stinger-benchmark-protocol",
            protocol_sha256=hashlib.sha256(protocol_bytes).hexdigest(),
            signature_sha256=hashlib.sha256(b"private protocol signature").hexdigest(),
            allowed_signers_sha256=hashlib.sha256(b"private allowed signers").hexdigest(),
            signing_key_fingerprint=f"SHA256:{'A' * 43}",
        ),
    )


def _manifest(
    kind: BundleKind,
    *,
    protocol_bytes: bytes,
    config_bytes: bytes,
    report_sha256: str,
    discriminator: bytes,
) -> EvidenceBundleManifest:
    """Create one deterministic manifest model for retained-receipt tests."""

    def digest(label: bytes) -> str:
        return hashlib.sha256(discriminator + label).hexdigest()

    return EvidenceBundleManifest(
        format_version="2",
        bundle_kind=kind,
        protocol_sha256=hashlib.sha256(protocol_bytes).hexdigest(),
        protocol_signature_sha256=digest(b"protocol-signature"),
        allowed_signers_sha256=digest(b"allowed-signers"),
        protocol_signer_identity="private-protocol-signer",
        protocol_signature_namespace="stinger-benchmark-protocol",
        config_sha256=hashlib.sha256(config_bytes).hexdigest(),
        report_sha256=report_sha256,
        inventory_sha256=digest(b"inventory"),
        leakage_policy_sha256=digest(b"leakage") if kind is BundleKind.PUBLIC else None,
        access_control_notice=None if kind is BundleKind.PUBLIC else "private escrow",
        files={},
        directories={},
    )


def _bundle_receipt(
    manifest: EvidenceBundleManifest,
    protocol: object,
    protocol_bytes: bytes,
    config: RunConfig,
    config_bytes: bytes,
    report: Report,
    report_bytes: bytes,
) -> EvidenceBundleReceipt:
    """Create one exact-byte public or escrow receipt."""
    assert protocol == compiled_benchmark_protocol()
    typed_protocol = compiled_benchmark_protocol()
    manifest_bytes = _canonical_bytes(manifest)
    return EvidenceBundleReceipt(
        bundle_kind=manifest.bundle_kind,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        protocol=typed_protocol,
        protocol_bytes=protocol_bytes,
        protocol_signature_bytes=b"private protocol signature",
        allowed_signers_bytes=b"private allowed signers",
        config=config,
        config_bytes=config_bytes,
        report=report,
        report_bytes=report_bytes,
    )


def _rebuild_report(
    receipt: VerifiedArtifactReceipt,
    results: list[ScenarioResult],
    *,
    corpus_hash: str | None = None,
) -> Report:
    """Recompute report aggregates after a deliberate test-only result mutation."""
    return build_report(
        results,
        corpus_hash=receipt.report.corpus_hash if corpus_hash is None else corpus_hash,
        config_fingerprint=receipt.report.config_fingerprint,
        generated_at=receipt.report.generated_at,
        benchmark_metadata=receipt.report.benchmark_metadata,
        benchmark_runtime_provenance=receipt.report.benchmark_runtime_provenance,
        bootstrap_samples=25,
    )


def _replace_report(
    receipt: VerifiedArtifactReceipt,
    report: Report,
) -> VerifiedArtifactReceipt:
    """Return an exact internally consistent receipt carrying a changed report."""
    return _verified_receipt(receipt.protocol, receipt.config, report)


def _install_verifier(
    monkeypatch: pytest.MonkeyPatch,
    receipts: dict[str, VerifiedArtifactReceipt],
) -> None:
    """Route private synthetic bundle names to retained verified receipts."""

    def verify(
        public_bundle: Path,
        escrow_bundle: Path,
        leakage_policy: PublicLeakagePolicy,
        *,
        trusted_allowed_signers: Path,
        expected_signer_identity: str,
    ) -> VerifiedArtifactReceipt:
        del escrow_bundle
        del leakage_policy
        del trusted_allowed_signers
        del expected_signer_identity
        return receipts[public_bundle.name]

    monkeypatch.setattr(pilot_module, "verify_evidence_bundle_pair", verify)


def _canonical_bytes(model: object) -> bytes:
    """Serialize a Pydantic model exactly as the pilot builder expects."""
    assert hasattr(model, "model_dump")
    payload = model.model_dump(mode="json")
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
