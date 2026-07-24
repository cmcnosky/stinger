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

import stinger.benchmark.records as records_module
import stinger.cli as cli_module
from stinger import BENCHMARK_PROTOCOL_VERSION
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
    BenchmarkProtocolManifest,
    BenchmarkReleaseSubmission,
    CorpusScenarioRecord,
    ErrorDispositionRecord,
    RepositorySize,
    SealedCorpusRecord,
    canonical_report_sha256,
    evaluate_baseline_configuration_record,
)
from stinger.benchmark.ordering import ScenarioOrderItem, deterministic_blocked_ids
from stinger.benchmark.protocol import BenchmarkRuntimeProvenance, BenchmarkSplit, ProviderId
from stinger.benchmark.records import (
    BaselineRecordError,
    build_baseline_configuration_record,
    write_baseline_configuration_record,
)
from stinger.benchmark.signing import sign_protocol
from stinger.cli import main
from stinger.config import AgentConfig, RunConfig
from stinger.harness.sandbox import Isolation
from stinger.models import DetectorResult, Family, Outcome, Report, ScenarioResult
from stinger.report.generate import build_report, render_json
from stinger.report.repro import write_repro_package
from stinger.scenario.loader import Scenario, corpus_hash, discover_scenarios

ROOT = Path(__file__).resolve().parents[1]
SIGNER_IDENTITY = "baseline-builder@example.test"
AGENT_DIGEST = f"sha256:{'a' * 64}"
VERIFICATION_DIGEST = f"sha256:{'b' * 64}"
STINGER_COMMIT = "c" * 40
CANARY = "STINGER-SYNTHETIC-SEALED-CANARY-41f703"
DUMMY_SECRET = "sk-dummy-stinger-synthetic-only-91b4c8"
RELEASE_SCHEMA_SHA256 = "e3e5047f3d40b51f7dc294fa457e227051f3583e3398dae573c47e61335ce095"


@dataclass(frozen=True, slots=True)
class BaselineArtifacts:
    """Reusable real bundle pair and its derived positive record."""

    root: Path
    corpus_path: Path
    corpus_record: SealedCorpusRecord
    protocol: Path
    public_bundle: Path
    escrow_bundle: Path
    policy: PublicLeakagePolicy
    allowed_signers: Path
    machine_identity: Path
    marker_files: tuple[Path, Path]
    config: RunConfig
    report: Report
    receipt: VerifiedArtifactReceipt
    record: BaselineConfigurationRecord


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
                    author_id=f"synthetic-author-{family.value.lower()}-{index % 4}",
                    provenance_recorded=True,
                    validity_passed=True,
                    held_out_oracle_passed=True,
                    containment_passed=True,
                    dummy_only_safety_data=True,
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
        resolved_agent_invocation=("recorded", "--model", "synthetic-model"),
        resolved_version_invocation=("recorded", "--version"),
        reasoning_effort=metadata.reasoning_effort,
        inference_settings=metadata.inference_settings,
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


@pytest.fixture(scope="module")
def baseline_artifacts(tmp_path_factory: pytest.TempPathFactory) -> BaselineArtifacts:
    """Build one real publication-grade fixture and reuse its expensive verification."""
    root = tmp_path_factory.mktemp("baseline-records")
    corpus_path = root / "sealed-corpus"
    corpus_path.mkdir()
    corpus_scenarios = _write_synthetic_corpus(corpus_path)
    scenarios = discover_scenarios(corpus_path)
    digest = corpus_hash(scenarios)
    corpus_record = SealedCorpusRecord(
        corpus_version="1.0.0",
        corpus_hash=digest,
        scenarios=corpus_scenarios,
        stored_outside_public_repository=True,
        access_logging_enabled=True,
        canary_checks_passed=True,
        frozen_before_baselines=True,
    )
    config = RunConfig(
        agent=AgentConfig(
            adapter="recorded",
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
        stinger_commit=STINGER_COMMIT,
        verification_image_digest=VERIFICATION_DIGEST,
        run_seed=17,
    )
    scenarios_by_id = {scenario.id: scenario for scenario in scenarios}
    report = _publication_report(scenarios_by_id, digest, config)

    evidence = root / "rerunnable-evidence"
    for result in report.results:
        transcript = evidence / result.transcript_path
        diff = evidence / result.diff_path
        transcript.parent.mkdir(parents=True, exist_ok=True)
        transcript.write_text("synthetic reviewed transcript\n", encoding="utf-8")
        diff.write_text("", encoding="utf-8")
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
    machine_identity = root / "machine.identity"
    machine_identity.write_bytes(b"synthetic-machine-attestation-v1\n")
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
        machine_identity_artifact=machine_identity,
    )
    return BaselineArtifacts(
        root=root,
        corpus_path=corpus_path,
        corpus_record=corpus_record,
        protocol=protocol,
        public_bundle=public_bundle,
        escrow_bundle=escrow_bundle,
        policy=policy,
        allowed_signers=allowed_signers,
        machine_identity=machine_identity,
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
    machine_identity: Path | None = None,
    dispositions: tuple[ErrorDispositionRecord, ...] = (),
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
        machine_identity_artifact=machine_identity or artifacts.machine_identity,
        error_dispositions=dispositions,
    )


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
        protocol=BenchmarkProtocolManifest(),
    )
    assert evaluation.eligible, evaluation.issues


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


def test_machine_identity_is_regular_nonsymlink_and_nonempty(
    tmp_path: Path,
    baseline_artifacts: BaselineArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Machine attestation bytes are bounded without accepting path substitutions."""
    empty = tmp_path / "empty.identity"
    empty.touch()
    with pytest.raises(BaselineRecordError, match="must not be empty"):
        _build_with_stubbed_receipt(
            baseline_artifacts,
            monkeypatch,
            machine_identity=empty,
        )

    link = tmp_path / "linked.identity"
    link.symlink_to(baseline_artifacts.machine_identity)
    with pytest.raises(BaselineRecordError, match="nonsymlink"):
        _build_with_stubbed_receipt(
            baseline_artifacts,
            monkeypatch,
            machine_identity=link,
        )

    directory = tmp_path / "directory.identity"
    directory.mkdir()
    with pytest.raises(BaselineRecordError, match="nonsymlink"):
        _build_with_stubbed_receipt(
            baseline_artifacts,
            monkeypatch,
            machine_identity=directory,
        )

    fifo = tmp_path / "fifo.identity"
    os.mkfifo(fifo)
    with pytest.raises(BaselineRecordError, match="nonsymlink"):
        records_module._sha256_identity_artifact(fifo)


def test_error_dispositions_are_unique_and_name_only_errors(
    baseline_artifacts: BaselineArtifacts,
) -> None:
    """Disposition records cannot explain a non-error or duplicate an error key."""
    first = baseline_artifacts.report.results[0]
    errored = first.model_copy(
        update={
            "outcome": Outcome.ERROR,
            "goal_met": False,
            "agent_claimed_done": False,
            "run_error": "synthetic harness failure",
        }
    )
    report = baseline_artifacts.report.model_copy(
        update={"results": [errored, *baseline_artifacts.report.results[1:]]}
    )
    disposition = ErrorDispositionRecord(
        scenario_id=errored.scenario_id,
        repetition=errored.repetition,
        explained=True,
        explanation="Reviewed synthetic harness failure.",
    )
    records_module._validate_error_dispositions((disposition,), report)

    with pytest.raises(BaselineRecordError, match="duplicate"):
        records_module._validate_error_dispositions(
            (disposition, disposition),
            report,
        )
    non_error = ErrorDispositionRecord(
        scenario_id=baseline_artifacts.report.results[1].scenario_id,
        repetition=baseline_artifacts.report.results[1].repetition,
        explained=True,
        explanation="Not actually an error.",
    )
    with pytest.raises(BaselineRecordError, match="observed ERROR"):
        records_module._validate_error_dispositions((non_error,), report)
    blank = disposition.model_copy(update={"explanation": "  "})
    with pytest.raises(BaselineRecordError, match="nonblank"):
        records_module._validate_error_dispositions((blank,), report)


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
            "--output",
            str(destination),
        ],
    )

    assert outcome.exit_code != 0
    assert "a marker file is empty" in outcome.output
    assert str(sensitive) not in outcome.output
    assert not destination.exists()


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


def test_release_schema_hash_is_unchanged() -> None:
    """The artifact builder does not change the signed release schema."""
    encoded = json.dumps(
        BenchmarkReleaseSubmission.model_json_schema(),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    assert hashlib.sha256(encoded).hexdigest() == RELEASE_SCHEMA_SHA256
