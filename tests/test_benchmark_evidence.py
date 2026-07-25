"""Public-vs-escrow benchmark evidence packaging and leakage safeguards."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

import stinger.benchmark.evidence as evidence_module
from stinger import BENCHMARK_PROTOCOL_VERSION
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
from stinger.benchmark.signing import sign_protocol
from stinger.cli import main
from stinger.config import AgentConfig, RunConfig
from stinger.models import Outcome, ScenarioResult
from stinger.report.generate import build_report, load_report, render_json
from stinger.report.repro import SEALED_REPRO_MARKER, write_repro_package
from stinger.scenario.loader import corpus_hash, discover_scenarios

CANARY = "STINGER-SEALED-CANARY-5b8f21"
BAIT_SECRET = "sk-dummy-stinger-bait-only-8fj2"
SIGNER_IDENTITY = "stinger-release@example.test"
ROOT = Path(__file__).resolve().parents[1]


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


@pytest.fixture
def evidence_inputs(tmp_path: Path, t02_dir: Path) -> dict[str, Path]:
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
            provider="other",
            cli_version="1.2.3",
            reasoning_effort="fixed",
            inference_settings={"temperature": 0},
            container_image="fixture-agent:1",
            container_image_digest="sha256:" + "1" * 64,
            credential_mount=root / "private" / "credentials",
        ),
        corpus=corpus,
        output_dir=root / "private" / "repro-output",
        reps=1,
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
        stinger_commit="2" * 40,
        verification_image_digest="sha256:" + "3" * 64,
        run_seed=7,
    )
    config.write_text(run_config.resolved_json(), encoding="utf-8")

    scenario = scenarios[0]
    result = ScenarioResult(
        scenario_id=scenario.id,
        family=scenario.manifest.family,
        outcome=Outcome.HONEST,
        detector_results=[],
        goal_met=True,
        agent_claimed_done=True,
        transcript_path=f"runs/{scenario.id}/0/transcript.txt",
        diff_path=f"runs/{scenario.id}/0/after.diff",
        duration_s=1.0,
        repetition=0,
        benchmark_split=scenario.manifest.benchmark_split,
        scenario_version=scenario.manifest.scenario_version,
        cluster_id=scenario.manifest.cluster_id,
    )
    built_report = build_report(
        [result],
        corpus_hash=corpus_hash(scenarios),
        config_fingerprint=run_config.fingerprint(),
        generated_at="2026-07-23T00:00:00+00:00",
        benchmark_metadata=run_config.benchmark_metadata(),
        bootstrap_samples=20,
    )
    report.write_text(render_json(built_report), encoding="utf-8")

    evidence = root / "repro"
    run_dir = evidence / "runs" / scenario.id / "0"
    run_dir.mkdir(parents=True)
    (run_dir / "transcript.txt").write_text("redacted transcript\n", encoding="utf-8")
    (run_dir / "after.diff").write_text("", encoding="utf-8")
    write_repro_package(evidence, built_report, run_config, scenarios)
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
        protocol=evidence_module.BenchmarkProtocolManifest(),
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

    def test_detects_core_path_substitution_after_verification(
        self,
        tmp_path: Path,
        evidence_inputs: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        public, active_policy = public_bundle(tmp_path / "public", evidence_inputs)
        escrow = escrow_bundle(tmp_path / "escrow", evidence_inputs)
        original = evidence_module.verify_public_evidence_bundle

        def verify_then_mutate(
            directory: Path,
            leakage_policy: PublicLeakagePolicy,
            *,
            trusted_allowed_signers: Path,
            expected_signer_identity: str,
        ) -> evidence_module.EvidenceBundleManifest:
            manifest = original(
                directory,
                leakage_policy,
                trusted_allowed_signers=trusted_allowed_signers,
                expected_signer_identity=expected_signer_identity,
            )
            (directory / "report" / "report.json").write_bytes(b"substituted")
            return manifest

        monkeypatch.setattr(
            evidence_module,
            "verify_public_evidence_bundle",
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
        original = evidence_module.verify_public_evidence_bundle

        def verify_then_add_file(
            directory: Path,
            leakage_policy: PublicLeakagePolicy,
            *,
            trusted_allowed_signers: Path,
            expected_signer_identity: str,
        ) -> evidence_module.EvidenceBundleManifest:
            manifest = original(
                directory,
                leakage_policy,
                trusted_allowed_signers=trusted_allowed_signers,
                expected_signer_identity=expected_signer_identity,
            )
            (directory / "post-verification-extra.txt").write_text(
                "not inventoried\n",
                encoding="utf-8",
            )
            return manifest

        monkeypatch.setattr(
            evidence_module,
            "verify_public_evidence_bundle",
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
        original = evidence_module.verify_escrow_evidence_bundle

        def verify_then_mutate(
            directory: Path,
            *,
            trusted_allowed_signers: Path,
            expected_signer_identity: str,
        ) -> evidence_module.EvidenceBundleManifest:
            manifest = original(
                directory,
                trusted_allowed_signers=trusted_allowed_signers,
                expected_signer_identity=expected_signer_identity,
            )
            (directory / "report" / "report.json").write_bytes(b"substituted")
            return manifest

        monkeypatch.setattr(
            evidence_module,
            "verify_escrow_evidence_bundle",
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
        original = evidence_module.verify_public_evidence_bundle
        marker_source = (
            evidence_inputs["corpus"] / "T-02-no-touch-tests" / "seed_repo" / "benchmark-bait.env"
        )

        def verify_then_mutate(
            directory: Path,
            leakage_policy: PublicLeakagePolicy,
            *,
            trusted_allowed_signers: Path,
            expected_signer_identity: str,
        ) -> evidence_module.EvidenceBundleManifest:
            manifest = original(
                directory,
                leakage_policy,
                trusted_allowed_signers=trusted_allowed_signers,
                expected_signer_identity=expected_signer_identity,
            )
            marker_source.write_text(
                f"CANARY={CANARY}\nBAIT={BAIT_SECRET}\nCHANGED=yes\n",
                encoding="utf-8",
            )
            return manifest

        monkeypatch.setattr(
            evidence_module,
            "verify_public_evidence_bundle",
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
        scenarios = discover_scenarios(evidence_inputs["corpus"])
        write_repro_package(
            evidence_inputs["evidence"],
            changed,
            run_config,
            scenarios,
        )

        with pytest.raises(EvidenceBundleError, match="metadata disagrees"):
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
        raw["total_scenarios"] = 119
        altered.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
        signature = sign_protocol(altered, evidence_inputs["private_key"])

        with pytest.raises(EvidenceBundleError, match="frozen Benchmark v1"):
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

        with pytest.raises(EvidenceBundleError, match="unsafe file"):
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
