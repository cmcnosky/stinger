"""Focused tests for artifact-derived release evidence construction."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

import pytest

import stinger.benchmark.release_evidence as release_evidence_module
from stinger.benchmark.gates import (
    BenchmarkReleaseSubmission,
    CorpusFreezeRecord,
    PilotEvidenceRecord,
    ReleaseEvidenceRecord,
    SealedCorpusRecord,
    compiled_benchmark_protocol,
)
from stinger.benchmark.release_evidence import (
    ConflictDisclosureEntry,
    MasterGateDistributionReceipt,
    MasterGateExecutableReceipt,
    MasterGateExecution,
    MasterGateWorkflowReceipt,
    PreparedReleaseEvidence,
    ReleaseEvidenceBuilderError,
    ReleaseEvidencePreparationReceipt,
    ReleaseEvidenceStatement,
    build_release_artifact_manifest,
    build_release_evidence_statement,
    canonical_benchmark_submission_sha256,
    canonical_release_evidence_record_sha256,
    load_release_evidence_preparation_package,
    prepare_release_evidence,
    release_evidence_record_from_artifacts,
    verify_release_evidence_statement,
    write_release_artifact,
    write_release_evidence_preparation_package,
    write_release_evidence_record,
    write_release_evidence_statement,
)

_CORPUS_HASH = "7" * 64
_CORPUS_VERSION = "1.0.0"
_TOOLCHAIN_PYTHON = Path(sys.executable).resolve()


@dataclass(frozen=True)
class _Artifacts:
    protocol_freeze: Path
    technical_report: Path
    correction_policy: Path
    conflicts_disclosure: Path
    vendor_rerun: Path


def _run_git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _repository(tmp_path: Path) -> tuple[Path, str]:
    repository = tmp_path / "checkout"
    scripts = repository / "scripts"
    scripts.mkdir(parents=True)
    check_script = scripts / "check.sh"
    check_script.write_text(
        "#!/bin/sh\n"
        'test "$PYTHONPATH" = "$PWD/src"\n'
        'test -n "$STINGER_CHECK_PYTHON"\n'
        'test ! -e "$PWD/.venv"\n'
        'printf "fixed environment ok\\n"\n',
        encoding="utf-8",
    )
    check_script.chmod(0o755)
    (repository / "tracked.txt").write_text("exact source\n", encoding="utf-8")
    _run_git(repository, "init")
    _run_git(repository, "config", "user.email", "release-builder@example.invalid")
    _run_git(repository, "config", "user.name", "Release Builder Test")
    _run_git(repository, "add", "scripts/check.sh", "tracked.txt")
    _run_git(repository, "commit", "-m", "test: exact release checkout")
    return repository, _run_git(repository, "rev-parse", "HEAD")


def _artifacts(tmp_path: Path) -> _Artifacts:
    evidence = tmp_path / "private-evidence"
    evidence.mkdir()
    paths = _Artifacts(
        protocol_freeze=evidence / "protocol-freeze.json",
        technical_report=evidence / "technical-report.md",
        correction_policy=evidence / "correction-policy.md",
        conflicts_disclosure=evidence / "conflicts.md",
        vendor_rerun=evidence / "vendor-rerun.json",
    )
    manifest = build_release_artifact_manifest(
        _submission_with_record(ReleaseEvidenceRecord()),
        conflicts_declaration="no-known-material-conflicts",
    )
    write_release_artifact(paths.protocol_freeze, manifest.protocol_freeze)
    write_release_artifact(paths.technical_report, manifest.technical_report)
    write_release_artifact(paths.correction_policy, manifest.correction_policy)
    write_release_artifact(paths.conflicts_disclosure, manifest.conflicts_disclosure)
    paths.vendor_rerun.write_bytes(b"comparative releases are intentionally held\n")
    return paths


def _prepare(
    repository: Path,
    commit: str,
    artifacts: _Artifacts,
    *,
    comparative: bool = False,
    execution: MasterGateExecution | None = None,
) -> PreparedReleaseEvidence:
    observed_execution = execution or MasterGateExecution(
        returncode=0,
        output=b"ruff, mypy, pytest, validation: all green\n",
    )
    with (
        patch.object(
            release_evidence_module,
            "_run_master_gate_subprocess",
            return_value=observed_execution,
        ),
        patch.object(
            release_evidence_module,
            "_executable_receipt",
            side_effect=_executable_receipt,
        ),
        patch.object(
            release_evidence_module,
            "_tool_distribution_receipts",
            return_value=_distribution_receipts(),
        ),
    ):
        return prepare_release_evidence(
            repository=repository,
            toolchain_python=_TOOLCHAIN_PYTHON,
            expected_stinger_commit=commit,
            corpus_version=_CORPUS_VERSION,
            corpus_hash=_CORPUS_HASH,
            protocol_freeze_receipt=artifacts.protocol_freeze,
            technical_report=artifacts.technical_report,
            correction_policy=artifacts.correction_policy,
            conflicts_disclosure=artifacts.conflicts_disclosure,
            comparative_release=comparative,
            vendor_rerun_receipt=artifacts.vendor_rerun if comparative else None,
        )


def _executable_receipt(
    name: str,
    _executable: Path,
    _version_arguments: tuple[str, ...],
) -> MasterGateExecutableReceipt:
    """Return one deterministic receipt at the private observation seam."""
    return MasterGateExecutableReceipt(
        name=name,
        sha256=hashlib.sha256(name.encode()).hexdigest(),
        version=f"{name} test-version",
    )


def _distribution_receipts() -> tuple[MasterGateDistributionReceipt, ...]:
    """Return a complete deterministic Python-tool inventory for focused tests."""
    return tuple(
        MasterGateDistributionReceipt(
            name=name,
            version="1.0.0",
            file_inventory_sha256=hashlib.sha256(name.encode()).hexdigest(),
            file_count=1,
        )
        for name in ("coverage", "mypy", "pytest", "pytest-cov", "ruff")
    )


def _canonical_model_sha256(model: MasterGateWorkflowReceipt) -> str:
    """Hash one typed receipt in the production canonical form."""
    content = (
        json.dumps(
            model.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
    return hashlib.sha256(content).hexdigest()


def _replace_canonical_model(path: Path, model: object) -> None:
    """Replace one temporary artifact with canonical JSON for adversarial tests."""
    assert hasattr(model, "model_dump")
    path.write_bytes(
        json.dumps(
            model.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


def _write_and_load(
    tmp_path: Path,
    repository: Path,
    commit: str,
    artifacts: _Artifacts,
    prepared: PreparedReleaseEvidence,
    *,
    comparative: bool = False,
) -> tuple[Path, PreparedReleaseEvidence]:
    package = tmp_path / "release-evidence-preparation"
    write_release_evidence_preparation_package(package, prepared)
    loaded = load_release_evidence_preparation_package(
        package,
        repository=repository,
        expected_stinger_commit=commit,
        corpus_version=_CORPUS_VERSION,
        corpus_hash=_CORPUS_HASH,
        protocol_freeze_receipt=artifacts.protocol_freeze,
        technical_report=artifacts.technical_report,
        correction_policy=artifacts.correction_policy,
        conflicts_disclosure=artifacts.conflicts_disclosure,
        comparative_release=comparative,
        vendor_rerun_receipt=artifacts.vendor_rerun if comparative else None,
    )
    return package, loaded


def _submission_with_record(record: ReleaseEvidenceRecord) -> BenchmarkReleaseSubmission:
    return BenchmarkReleaseSubmission(
        protocol=compiled_benchmark_protocol(),
        corpus=SealedCorpusRecord(
            corpus_version=_CORPUS_VERSION,
            corpus_hash=_CORPUS_HASH,
            scenarios=(),
            freeze=CorpusFreezeRecord(
                signer_identity="freeze-authority@example.invalid",
                statement_sha256="1" * 64,
                statement_signature_sha256="2" * 64,
                allowed_signers_sha256="3" * 64,
            ),
        ),
        baselines=(),
        pilot=PilotEvidenceRecord(),
        conformance_environments=(),
        cross_machine_reproduction=None,
        release_evidence=record,
        human_approval=None,
    )


def _submission(prepared: PreparedReleaseEvidence) -> BenchmarkReleaseSubmission:
    return _submission_with_record(prepared.record)


def test_builds_exact_noncomparative_record_and_finalized_statement(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    output = b"exact private master-gate output\n"
    prepared = _prepare(
        repository,
        commit,
        artifacts,
        execution=MasterGateExecution(returncode=0, output=output),
    )

    assert (
        prepared.record.protocol_freeze_receipt_sha256
        == hashlib.sha256(artifacts.protocol_freeze.read_bytes()).hexdigest()
    )
    assert prepared.record.master_gate_receipt_sha256 == _canonical_model_sha256(
        prepared.master_gate_receipt
    )
    assert (
        prepared.record.technical_report_sha256
        == hashlib.sha256(artifacts.technical_report.read_bytes()).hexdigest()
    )
    assert (
        prepared.record.correction_policy_sha256
        == hashlib.sha256(artifacts.correction_policy.read_bytes()).hexdigest()
    )
    assert (
        prepared.record.conflicts_disclosure_sha256
        == hashlib.sha256(artifacts.conflicts_disclosure.read_bytes()).hexdigest()
    )
    assert prepared.record.comparative_release is False
    assert prepared.record.vendor_rerun_receipt_sha256 is None
    package, loaded = _write_and_load(
        tmp_path,
        repository,
        commit,
        artifacts,
        prepared,
    )
    assert loaded == prepared
    assert sorted(path.name for path in package.iterdir()) == [
        "master-gate-output.bin",
        "master-gate-receipt.json",
        "preparation-receipt.json",
    ]
    assert (package / "master-gate-output.bin").read_bytes() == output
    receipt_bytes = (package / "preparation-receipt.json").read_bytes()
    receipt_payload = json.loads(receipt_bytes)
    assert receipt_payload == prepared.receipt.model_dump(mode="json")
    assert str(repository) not in receipt_bytes.decode()
    for artifact in (
        artifacts.protocol_freeze,
        artifacts.technical_report,
        artifacts.correction_policy,
        artifacts.conflicts_disclosure,
    ):
        assert str(artifact) not in receipt_bytes.decode()
    assert package.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in package.iterdir())

    submission = _submission(loaded)
    statement = build_release_evidence_statement(
        submission,
        loaded,
        signer_identity="release-evidence@example.invalid",
    )

    assert statement.stinger_commit == commit
    assert statement.release_evidence_record_sha256 == (
        canonical_release_evidence_record_sha256(loaded.record)
    )
    assert statement.canonical_submission_sha256 == (
        canonical_benchmark_submission_sha256(submission)
    )
    assert output.decode().strip() not in statement.model_dump_json()
    verify_release_evidence_statement(statement, submission)


def test_comparative_release_is_explicitly_held_until_signed_vendor_evidence(
    tmp_path: Path,
) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)

    with pytest.raises(ReleaseEvidenceBuilderError, match="comparative publication is on HOLD"):
        _prepare(repository, commit, artifacts, comparative=True)


@pytest.mark.parametrize(
    "artifact_name",
    [
        "protocol_freeze",
        "technical_report",
        "correction_policy",
        "conflicts_disclosure",
    ],
)
def test_arbitrary_nonempty_bytes_cannot_satisfy_release_artifact_claims(
    tmp_path: Path,
    artifact_name: str,
) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    getattr(artifacts, artifact_name).write_bytes(b"arbitrary but nonempty caller bytes\n")

    with pytest.raises(ReleaseEvidenceBuilderError, match="closed schema"):
        _prepare(repository, commit, artifacts)


def test_correction_obligations_cannot_be_omitted_from_canonical_json(
    tmp_path: Path,
) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    payload = json.loads(artifacts.correction_policy.read_bytes())
    payload["required_actions"] = payload["required_actions"][:-1]
    artifacts.correction_policy.write_bytes(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )

    with pytest.raises(ReleaseEvidenceBuilderError, match="closed schema"):
        _prepare(repository, commit, artifacts)


def test_technical_report_rejects_caller_authored_prose_fields(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    payload = json.loads(artifacts.technical_report.read_bytes())
    payload["sections"][0]["body"] = (
        "A caller-authored paragraph could hide an implicit vendor comparison and is forbidden."
    )
    artifacts.technical_report.write_bytes(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )

    with pytest.raises(ReleaseEvidenceBuilderError, match="closed schema"):
        _prepare(repository, commit, artifacts)


def test_typed_but_false_freeze_binding_is_rejected_against_final_submission(
    tmp_path: Path,
) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    draft = _submission_with_record(ReleaseEvidenceRecord())
    assert draft.corpus.freeze is not None
    false_draft = draft.model_copy(
        update={
            "corpus": draft.corpus.model_copy(
                update={
                    "freeze": draft.corpus.freeze.model_copy(update={"statement_sha256": "9" * 64})
                }
            )
        }
    )
    false_manifest = build_release_artifact_manifest(
        false_draft,
        conflicts_declaration="no-known-material-conflicts",
    )
    _replace_canonical_model(artifacts.protocol_freeze, false_manifest.protocol_freeze)
    _replace_canonical_model(artifacts.technical_report, false_manifest.technical_report)
    _replace_canonical_model(artifacts.correction_policy, false_manifest.correction_policy)
    _replace_canonical_model(
        artifacts.conflicts_disclosure,
        false_manifest.conflicts_disclosure,
    )
    prepared = _prepare(repository, commit, artifacts)

    with pytest.raises(ReleaseEvidenceBuilderError, match="exact typed submission"):
        build_release_evidence_statement(
            _submission(prepared),
            prepared,
            signer_identity="release-evidence@example.invalid",
        )


def test_conflict_declaration_is_closed_and_internally_consistent() -> None:
    relationship = ConflictDisclosureEntry(
        category="advisory",
        entity="Example Provider",
        description=(
            "The release signer provided a paid advisory engagement during the covered period."
        ),
    )
    with pytest.raises(ValueError, match="inconsistent"):
        build_release_artifact_manifest(
            _submission_with_record(ReleaseEvidenceRecord()),
            conflicts_declaration="no-known-material-conflicts",
            conflict_relationships=(relationship,),
        )


def test_rejects_artifact_and_finalized_submission_tampering(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    prepared = _prepare(repository, commit, artifacts)
    submission = _submission(prepared)

    original_report = artifacts.technical_report.read_bytes()
    artifacts.technical_report.write_text("substituted report\n", encoding="utf-8")
    with pytest.raises(ReleaseEvidenceBuilderError, match="artifact changed"):
        build_release_evidence_statement(
            submission,
            prepared,
            signer_identity="release-evidence@example.invalid",
        )

    artifacts.technical_report.write_bytes(original_report)
    statement = build_release_evidence_statement(
        submission,
        prepared,
        signer_identity="release-evidence@example.invalid",
    )
    altered = submission.model_copy(
        update={
            "corpus": submission.corpus.model_copy(
                update={"corpus_hash": "8" * 64},
            )
        }
    )
    with pytest.raises(ReleaseEvidenceBuilderError, match="exact submission"):
        verify_release_evidence_statement(statement, altered)


def test_rejects_dirty_checkout_before_gate(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    (repository / "untracked-private-name.txt").write_text("dirty\n", encoding="utf-8")

    with pytest.raises(ReleaseEvidenceBuilderError) as captured:
        _prepare(repository, commit, artifacts)

    assert str(repository) not in str(captured.value)
    assert "untracked-private-name" not in str(captured.value)
    assert "clean at an exact commit" in str(captured.value)


def test_rejects_checkout_dirtied_by_gate(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)

    def dirty_gate(
        _argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str],
    ) -> MasterGateExecution:
        del cwd, environment
        (repository / "gate-created.tmp").write_text("unexpected\n", encoding="utf-8")
        return MasterGateExecution(returncode=0, output=b"apparently green\n")

    with (
        patch.object(
            release_evidence_module,
            "_run_master_gate_subprocess",
            side_effect=dirty_gate,
        ),
        patch.object(
            release_evidence_module,
            "_executable_receipt",
            side_effect=_executable_receipt,
        ),
        patch.object(
            release_evidence_module,
            "_tool_distribution_receipts",
            return_value=_distribution_receipts(),
        ),
        pytest.raises(ReleaseEvidenceBuilderError) as captured,
    ):
        prepare_release_evidence(
            repository=repository,
            toolchain_python=_TOOLCHAIN_PYTHON,
            expected_stinger_commit=commit,
            corpus_version=_CORPUS_VERSION,
            corpus_hash=_CORPUS_HASH,
            protocol_freeze_receipt=artifacts.protocol_freeze,
            technical_report=artifacts.technical_report,
            correction_policy=artifacts.correction_policy,
            conflicts_disclosure=artifacts.conflicts_disclosure,
        )

    assert str(repository) not in str(captured.value)
    assert "gate-created.tmp" not in str(captured.value)
    assert "changed during master-gate" in str(captured.value)


def test_rejects_failing_gate_without_disclosing_output(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    private_output = b"failure at /private/hidden/path with token SECRET-VALUE\n"

    with pytest.raises(ReleaseEvidenceBuilderError) as captured:
        _prepare(
            repository,
            commit,
            artifacts,
            execution=MasterGateExecution(returncode=1, output=private_output),
        )

    message = str(captured.value)
    assert message == "master gate did not pass"
    assert "SECRET-VALUE" not in message
    assert "/private/hidden/path" not in message


def test_master_gate_timeout_kills_the_private_process_group_and_reaps_the_leader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TimedOutGate:
        pid = 515151
        returncode: int | None = None
        communicate_calls = 0

        def communicate(self, *, timeout: int) -> tuple[bytes, None]:
            self.communicate_calls += 1
            if self.communicate_calls == 1:
                assert timeout == release_evidence_module._MASTER_GATE_TIMEOUT_SECONDS
                raise subprocess.TimeoutExpired("scripts/check.sh", timeout)
            assert timeout == release_evidence_module._MASTER_GATE_REAP_TIMEOUT_SECONDS
            self.returncode = -9
            return b"", None

        def poll(self) -> int | None:
            return self.returncode

    process = TimedOutGate()
    launch_options: list[dict[str, object]] = []
    killed_groups: list[int] = []

    def launch(*_args: object, **kwargs: object) -> TimedOutGate:
        launch_options.append(kwargs)
        return process

    monkeypatch.setattr(release_evidence_module.subprocess, "Popen", launch)
    monkeypatch.setattr(
        release_evidence_module.os,
        "killpg",
        lambda process_group, signal_number: killed_groups.append(process_group),
    )

    with pytest.raises(ReleaseEvidenceBuilderError, match="master gate execution failed"):
        release_evidence_module._run_master_gate_subprocess(
            ("/bin/bash", "scripts/check.sh"),
            cwd=tmp_path,
            environment={},
        )

    assert launch_options[0]["start_new_session"] is True
    assert killed_groups == [process.pid]
    assert process.communicate_calls == 2


@pytest.mark.parametrize(
    "interruption",
    [KeyboardInterrupt(), SystemExit(17), BaseException("synthetic stop")],
    ids=["keyboard-interrupt", "system-exit", "base-exception"],
)
def test_master_gate_interruption_cleans_the_process_group_then_reraises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interruption: BaseException,
) -> None:
    class InterruptedGate:
        pid = 515152
        returncode: int | None = None
        communicate_calls = 0

        def communicate(self, *, timeout: int) -> tuple[bytes, None]:
            self.communicate_calls += 1
            if self.communicate_calls == 1:
                raise interruption
            assert timeout == release_evidence_module._MASTER_GATE_REAP_TIMEOUT_SECONDS
            self.returncode = -9
            return b"", None

        def poll(self) -> int | None:
            return self.returncode

    process = InterruptedGate()
    killed_groups: list[int] = []
    monkeypatch.setattr(
        release_evidence_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        release_evidence_module.os,
        "killpg",
        lambda process_group, signal_number: killed_groups.append(process_group),
    )

    with pytest.raises(type(interruption)):
        release_evidence_module._run_master_gate_subprocess(
            ("/bin/bash", "scripts/check.sh"),
            cwd=tmp_path,
            environment={},
        )

    assert killed_groups == [process.pid]
    assert process.communicate_calls == 2


def test_successful_master_gate_still_terminates_background_descendants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SuccessfulGate:
        pid = 515153
        returncode: int | None = None

        def communicate(self, *, timeout: int) -> tuple[bytes, None]:
            assert timeout == release_evidence_module._MASTER_GATE_TIMEOUT_SECONDS
            self.returncode = 0
            return b"green\n", None

        def poll(self) -> int | None:
            return self.returncode

    process = SuccessfulGate()
    killed_groups: list[int] = []
    monkeypatch.setattr(
        release_evidence_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        release_evidence_module.os,
        "killpg",
        lambda process_group, signal_number: killed_groups.append(process_group),
    )

    execution = release_evidence_module._run_master_gate_subprocess(
        ("/bin/bash", "scripts/check.sh"),
        cwd=tmp_path,
        environment={},
    )

    assert execution == MasterGateExecution(returncode=0, output=b"green\n")
    assert killed_groups == [process.pid]


def test_default_gate_uses_explicit_toolchain_and_tracked_snapshot(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)

    with (
        patch.object(
            release_evidence_module,
            "_executable_receipt",
            side_effect=_executable_receipt,
        ),
        patch.object(
            release_evidence_module,
            "_tool_distribution_receipts",
            return_value=_distribution_receipts(),
        ),
    ):
        prepared = prepare_release_evidence(
            repository=repository,
            toolchain_python=_TOOLCHAIN_PYTHON,
            expected_stinger_commit=commit,
            corpus_version=_CORPUS_VERSION,
            corpus_hash=_CORPUS_HASH,
            protocol_freeze_receipt=artifacts.protocol_freeze,
            technical_report=artifacts.technical_report,
            correction_policy=artifacts.correction_policy,
            conflicts_disclosure=artifacts.conflicts_disclosure,
        )

    assert prepared.master_gate_output == b"fixed environment ok\n"
    assert prepared.master_gate_receipt.command == ("bash", "scripts/check.sh")


def test_statement_output_is_closed_canonical_and_no_overwrite(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    prepared = _prepare(repository, commit, artifacts)
    statement = build_release_evidence_statement(
        _submission(prepared),
        prepared,
        signer_identity="release-evidence@example.invalid",
    )
    destination = tmp_path / "public" / "release-evidence-statement.json"
    record_destination = tmp_path / "public" / "release-evidence-record.json"

    write_release_evidence_record(record_destination, prepared.record)
    write_release_evidence_statement(destination, statement)
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload == statement.model_dump(mode="json")
    assert destination.read_bytes().endswith(b"\n")
    ReleaseEvidenceStatement.model_validate(payload)

    with pytest.raises(ReleaseEvidenceBuilderError, match="already exists"):
        write_release_evidence_statement(destination, statement)
    with pytest.raises(ReleaseEvidenceBuilderError, match="already exists"):
        write_release_evidence_record(record_destination, prepared.record)
    assert json.loads(destination.read_text(encoding="utf-8")) == payload


def test_rejects_symlink_artifact(tmp_path: Path) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlinks unavailable")
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    link = tmp_path / "linked-report.md"
    link.symlink_to(artifacts.technical_report)

    with pytest.raises(ReleaseEvidenceBuilderError, match="artifact is unavailable"):
        prepare_release_evidence(
            repository=repository,
            toolchain_python=_TOOLCHAIN_PYTHON,
            expected_stinger_commit=commit,
            corpus_version=_CORPUS_VERSION,
            corpus_hash=_CORPUS_HASH,
            protocol_freeze_receipt=artifacts.protocol_freeze,
            technical_report=link,
            correction_policy=artifacts.correction_policy,
            conflicts_disclosure=artifacts.conflicts_disclosure,
        )


def test_persisted_preparation_is_reused_without_second_gate_execution(
    tmp_path: Path,
) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    executions = 0

    def nondeterministic_gate(
        _argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str],
    ) -> MasterGateExecution:
        del cwd, environment
        nonlocal executions
        executions += 1
        return MasterGateExecution(
            returncode=0,
            output=f"green execution {executions}\n".encode(),
        )

    with (
        patch.object(
            release_evidence_module,
            "_run_master_gate_subprocess",
            side_effect=nondeterministic_gate,
        ),
        patch.object(
            release_evidence_module,
            "_executable_receipt",
            side_effect=_executable_receipt,
        ),
        patch.object(
            release_evidence_module,
            "_tool_distribution_receipts",
            return_value=_distribution_receipts(),
        ),
    ):
        prepared = prepare_release_evidence(
            repository=repository,
            toolchain_python=_TOOLCHAIN_PYTHON,
            expected_stinger_commit=commit,
            corpus_version=_CORPUS_VERSION,
            corpus_hash=_CORPUS_HASH,
            protocol_freeze_receipt=artifacts.protocol_freeze,
            technical_report=artifacts.technical_report,
            correction_policy=artifacts.correction_policy,
            conflicts_disclosure=artifacts.conflicts_disclosure,
        )
    _, loaded = _write_and_load(tmp_path, repository, commit, artifacts, prepared)
    statement = build_release_evidence_statement(
        _submission(loaded),
        loaded,
        signer_identity="release-evidence@example.invalid",
    )

    assert executions == 1
    assert loaded.master_gate_output == b"green execution 1\n"
    assert statement.release_evidence.master_gate_receipt_sha256 == (
        _canonical_model_sha256(prepared.master_gate_receipt)
    )


def test_rejects_no_master_gate_output(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)

    with pytest.raises(ReleaseEvidenceBuilderError, match="no receipt output"):
        _prepare(
            repository,
            commit,
            artifacts,
            execution=MasterGateExecution(returncode=0, output=b""),
        )


@pytest.mark.parametrize(
    ("member", "replacement"),
    [
        ("master-gate-output.bin", b"different gate output\n"),
        ("master-gate-receipt.json", b"{}\n"),
        ("preparation-receipt.json", b"{}\n"),
    ],
)
def test_rejects_preparation_member_mutation(
    tmp_path: Path,
    member: str,
    replacement: bytes,
) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    prepared = _prepare(repository, commit, artifacts)
    package = tmp_path / "preparation"
    write_release_evidence_preparation_package(package, prepared)
    (package / member).write_bytes(replacement)

    with pytest.raises(ReleaseEvidenceBuilderError) as captured:
        load_release_evidence_preparation_package(
            package,
            repository=repository,
            expected_stinger_commit=commit,
            corpus_version=_CORPUS_VERSION,
            corpus_hash=_CORPUS_HASH,
            protocol_freeze_receipt=artifacts.protocol_freeze,
            technical_report=artifacts.technical_report,
            correction_policy=artifacts.correction_policy,
            conflicts_disclosure=artifacts.conflicts_disclosure,
        )

    assert str(package) not in str(captured.value)
    assert replacement.decode().strip() not in str(captured.value)


@pytest.mark.parametrize(
    "member",
    [
        "master-gate-output.bin",
        "master-gate-receipt.json",
        "preparation-receipt.json",
    ],
)
def test_rejects_partial_preparation_package(tmp_path: Path, member: str) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    prepared = _prepare(repository, commit, artifacts)
    package = tmp_path / "preparation"
    write_release_evidence_preparation_package(package, prepared)
    (package / member).unlink()

    with pytest.raises(ReleaseEvidenceBuilderError, match="incomplete or has extra files"):
        load_release_evidence_preparation_package(
            package,
            repository=repository,
            expected_stinger_commit=commit,
            corpus_version=_CORPUS_VERSION,
            corpus_hash=_CORPUS_HASH,
            protocol_freeze_receipt=artifacts.protocol_freeze,
            technical_report=artifacts.technical_report,
            correction_policy=artifacts.correction_policy,
            conflicts_disclosure=artifacts.conflicts_disclosure,
        )


def test_rejects_extra_preparation_package_file(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    prepared = _prepare(repository, commit, artifacts)
    package = tmp_path / "preparation"
    write_release_evidence_preparation_package(package, prepared)
    (package / "untrusted-extra").write_bytes(b"not evidence\n")

    with pytest.raises(ReleaseEvidenceBuilderError, match="incomplete or has extra files"):
        load_release_evidence_preparation_package(
            package,
            repository=repository,
            expected_stinger_commit=commit,
            corpus_version=_CORPUS_VERSION,
            corpus_hash=_CORPUS_HASH,
            protocol_freeze_receipt=artifacts.protocol_freeze,
            technical_report=artifacts.technical_report,
            correction_policy=artifacts.correction_policy,
            conflicts_disclosure=artifacts.conflicts_disclosure,
        )


def test_rejects_symlink_preparation_package_and_member(tmp_path: Path) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlinks unavailable")
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    prepared = _prepare(repository, commit, artifacts)
    package = tmp_path / "preparation"
    write_release_evidence_preparation_package(package, prepared)
    package_link = tmp_path / "preparation-link"
    package_link.symlink_to(package, target_is_directory=True)

    with pytest.raises(ReleaseEvidenceBuilderError, match="package is unavailable"):
        load_release_evidence_preparation_package(
            package_link,
            repository=repository,
            expected_stinger_commit=commit,
            corpus_version=_CORPUS_VERSION,
            corpus_hash=_CORPUS_HASH,
            protocol_freeze_receipt=artifacts.protocol_freeze,
            technical_report=artifacts.technical_report,
            correction_policy=artifacts.correction_policy,
            conflicts_disclosure=artifacts.conflicts_disclosure,
        )

    output = package / "master-gate-output.bin"
    preserved = tmp_path / "preserved-output"
    output.rename(preserved)
    output.symlink_to(preserved)
    with pytest.raises(ReleaseEvidenceBuilderError, match="output is unavailable"):
        load_release_evidence_preparation_package(
            package,
            repository=repository,
            expected_stinger_commit=commit,
            corpus_version=_CORPUS_VERSION,
            corpus_hash=_CORPUS_HASH,
            protocol_freeze_receipt=artifacts.protocol_freeze,
            technical_report=artifacts.technical_report,
            correction_policy=artifacts.correction_policy,
            conflicts_disclosure=artifacts.conflicts_disclosure,
        )


def test_rejects_noncanonical_or_duplicate_preparation_receipt(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    prepared = _prepare(repository, commit, artifacts)
    package = tmp_path / "preparation"
    write_release_evidence_preparation_package(package, prepared)
    receipt = package / "preparation-receipt.json"
    canonical = receipt.read_bytes()
    receipt.write_bytes(b'{"format_version":"1",' + canonical[1:])

    with pytest.raises(ReleaseEvidenceBuilderError, match="receipt is invalid"):
        load_release_evidence_preparation_package(
            package,
            repository=repository,
            expected_stinger_commit=commit,
            corpus_version=_CORPUS_VERSION,
            corpus_hash=_CORPUS_HASH,
            protocol_freeze_receipt=artifacts.protocol_freeze,
            technical_report=artifacts.technical_report,
            correction_policy=artifacts.correction_policy,
            conflicts_disclosure=artifacts.conflicts_disclosure,
        )

    receipt.write_bytes(canonical + b" ")
    with pytest.raises(ReleaseEvidenceBuilderError, match="receipt is not canonical"):
        load_release_evidence_preparation_package(
            package,
            repository=repository,
            expected_stinger_commit=commit,
            corpus_version=_CORPUS_VERSION,
            corpus_hash=_CORPUS_HASH,
            protocol_freeze_receipt=artifacts.protocol_freeze,
            technical_report=artifacts.technical_report,
            correction_policy=artifacts.correction_policy,
            conflicts_disclosure=artifacts.conflicts_disclosure,
        )


def test_rejects_artifact_or_checkout_change_when_loading_package(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    prepared = _prepare(repository, commit, artifacts)
    package = tmp_path / "preparation"
    write_release_evidence_preparation_package(package, prepared)
    original_policy = artifacts.correction_policy.read_bytes()
    artifacts.correction_policy.write_bytes(b"private path /do/not/disclose\n")

    with pytest.raises(ReleaseEvidenceBuilderError) as captured:
        load_release_evidence_preparation_package(
            package,
            repository=repository,
            expected_stinger_commit=commit,
            corpus_version=_CORPUS_VERSION,
            corpus_hash=_CORPUS_HASH,
            protocol_freeze_receipt=artifacts.protocol_freeze,
            technical_report=artifacts.technical_report,
            correction_policy=artifacts.correction_policy,
            conflicts_disclosure=artifacts.conflicts_disclosure,
        )
    assert str(artifacts.correction_policy) not in str(captured.value)
    assert "/do/not/disclose" not in str(captured.value)

    artifacts.correction_policy.write_bytes(original_policy)
    (repository / "untracked-secret-name").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(ReleaseEvidenceBuilderError) as checkout_captured:
        load_release_evidence_preparation_package(
            package,
            repository=repository,
            expected_stinger_commit=commit,
            corpus_version=_CORPUS_VERSION,
            corpus_hash=_CORPUS_HASH,
            protocol_freeze_receipt=artifacts.protocol_freeze,
            technical_report=artifacts.technical_report,
            correction_policy=artifacts.correction_policy,
            conflicts_disclosure=artifacts.conflicts_disclosure,
        )
    assert str(repository) not in str(checkout_captured.value)
    assert "untracked-secret-name" not in str(checkout_captured.value)


def test_rejects_preparation_package_toctou(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    prepared = _prepare(repository, commit, artifacts)
    package = tmp_path / "preparation"
    write_release_evidence_preparation_package(package, prepared)
    original_reader = release_evidence_module._read_preparation_package
    reads = 0

    def mutate_after_first_read(path: Path) -> tuple[bytes, bytes, bytes]:
        nonlocal reads
        observed = original_reader(path)
        reads += 1
        if reads == 1:
            (package / "master-gate-output.bin").write_bytes(b"mutated between reads\n")
        return observed

    monkeypatch.setattr(
        release_evidence_module,
        "_read_preparation_package",
        mutate_after_first_read,
    )
    with pytest.raises(ReleaseEvidenceBuilderError, match="changed during verification"):
        load_release_evidence_preparation_package(
            package,
            repository=repository,
            expected_stinger_commit=commit,
            corpus_version=_CORPUS_VERSION,
            corpus_hash=_CORPUS_HASH,
            protocol_freeze_receipt=artifacts.protocol_freeze,
            technical_report=artifacts.technical_report,
            correction_policy=artifacts.correction_policy,
            conflicts_disclosure=artifacts.conflicts_disclosure,
        )


def test_preparation_package_is_create_only_and_failed_publish_leaves_no_partial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    prepared = _prepare(repository, commit, artifacts)
    package = tmp_path / "preparation"
    write_release_evidence_preparation_package(package, prepared)
    original = {path.name: path.read_bytes() for path in package.iterdir()}
    with pytest.raises(ReleaseEvidenceBuilderError, match="already exists"):
        write_release_evidence_preparation_package(package, prepared)
    assert {path.name: path.read_bytes() for path in package.iterdir()} == original

    failed_package = tmp_path / "failed-preparation"

    def fail_publish(_source: Path, _destination: Path) -> None:
        raise ReleaseEvidenceBuilderError("simulated atomic publication failure")

    monkeypatch.setattr(
        release_evidence_module,
        "_rename_directory_noreplace",
        fail_publish,
    )
    with pytest.raises(ReleaseEvidenceBuilderError, match="simulated"):
        write_release_evidence_preparation_package(failed_package, prepared)
    assert not failed_package.exists()
    assert not list(tmp_path.glob(".failed-preparation.*.tmp"))


def test_preparation_receipt_model_is_closed_and_path_free() -> None:
    manifest = build_release_artifact_manifest(
        _submission_with_record(ReleaseEvidenceRecord()),
        conflicts_declaration="no-known-material-conflicts",
    )
    record = release_evidence_record_from_artifacts(
        manifest,
        master_gate_receipt_sha256="2" * 64,
    )
    payload = {
        "format_version": "3",
        "benchmark_protocol_version": "2.0.0",
        "rubric_version": "1.0.0",
        "corpus_version": _CORPUS_VERSION,
        "corpus_hash": _CORPUS_HASH,
        "stinger_commit": "a" * 40,
        "release_evidence": record.model_dump(mode="json"),
        "release_artifacts": manifest.model_dump(mode="json"),
        "release_evidence_record_sha256": canonical_release_evidence_record_sha256(record),
        "master_gate_workflow_receipt_sha256": "2" * 64,
        "master_gate_output_size_bytes": 1,
        "private_path": "/must/not/be-accepted",
    }
    with pytest.raises(ValueError):
        ReleaseEvidencePreparationReceipt.model_validate(payload)
