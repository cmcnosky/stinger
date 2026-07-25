"""CLI coverage for the persisted two-stage release-evidence workflow."""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

import stinger.benchmark.release_evidence as release_evidence_module
import stinger.cli as cli_module
from stinger.benchmark.gates import (
    BenchmarkReleaseSubmission,
    CorpusFreezeRecord,
    PilotEvidenceRecord,
    ReleaseEvidenceRecord,
    SealedCorpusRecord,
    compiled_benchmark_protocol,
)
from stinger.benchmark.release_evidence import (
    MasterGateDistributionReceipt,
    MasterGateExecutableReceipt,
    MasterGateExecution,
    build_release_artifact_manifest,
    write_release_artifact,
)
from stinger.cli import main

_CORPUS_HASH = "7" * 64
_CORPUS_VERSION = "1.0.0"
_SIGNER_IDENTITY = "release-evidence@example.invalid"
_TOOLCHAIN_PYTHON = Path(sys.executable).resolve()


@dataclass(frozen=True)
class _Artifacts:
    """Exact private release artifacts passed to both CLI stages."""

    protocol_freeze: Path
    technical_report: Path
    correction_policy: Path
    conflicts_disclosure: Path


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
    check_script.write_text("#!/bin/sh\nprintf 'unrepeatable gate output\\n'\n", encoding="utf-8")
    check_script.chmod(0o755)
    (repository / "tracked.txt").write_text("exact source\n", encoding="utf-8")
    _run_git(repository, "init")
    _run_git(repository, "config", "user.email", "release-cli@example.invalid")
    _run_git(repository, "config", "user.name", "Release CLI Test")
    _run_git(repository, "add", "scripts/check.sh", "tracked.txt")
    _run_git(repository, "commit", "-m", "test: release CLI checkout")
    return repository, _run_git(repository, "rev-parse", "HEAD")


def _artifacts(tmp_path: Path) -> _Artifacts:
    root = tmp_path / "private-release-artifacts"
    root.mkdir()
    artifacts = _Artifacts(
        protocol_freeze=root / "protocol-freeze.json",
        technical_report=root / "technical-report.md",
        correction_policy=root / "correction-policy.md",
        conflicts_disclosure=root / "conflicts.md",
    )
    manifest = build_release_artifact_manifest(
        _submission(ReleaseEvidenceRecord()),
        conflicts_declaration="no-known-material-conflicts",
    )
    write_release_artifact(artifacts.protocol_freeze, manifest.protocol_freeze)
    write_release_artifact(artifacts.technical_report, manifest.technical_report)
    write_release_artifact(artifacts.correction_policy, manifest.correction_policy)
    write_release_artifact(artifacts.conflicts_disclosure, manifest.conflicts_disclosure)
    return artifacts


def _artifact_options(
    repository: Path,
    commit: str,
    artifacts: _Artifacts,
    *,
    include_toolchain: bool = False,
) -> list[str]:
    """Return shared stage options, adding the explicit toolchain only for stage one."""
    options = [
        "--repository",
        str(repository),
        "--expected-stinger-commit",
        commit,
        "--corpus-version",
        _CORPUS_VERSION,
        "--corpus-hash",
        _CORPUS_HASH,
        "--protocol-freeze-receipt",
        str(artifacts.protocol_freeze),
        "--technical-report",
        str(artifacts.technical_report),
        "--correction-policy",
        str(artifacts.correction_policy),
        "--conflicts-disclosure",
        str(artifacts.conflicts_disclosure),
        "--non-comparative-release",
    ]
    if include_toolchain:
        options[2:2] = ["--toolchain-python", str(_TOOLCHAIN_PYTHON)]
    return options


def _submission(record: ReleaseEvidenceRecord) -> BenchmarkReleaseSubmission:
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


def _write_submission(path: Path, record_path: Path) -> None:
    record = ReleaseEvidenceRecord.model_validate_json(record_path.read_bytes())
    submission = _submission(record)
    path.write_text(
        json.dumps(
            submission.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )


def test_cli_builds_closed_release_artifact_package(tmp_path: Path) -> None:
    submission_path = tmp_path / "draft-submission.json"
    submission_path.write_text(
        json.dumps(
            _submission(ReleaseEvidenceRecord()).model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "release-artifacts"

    result = CliRunner().invoke(
        main,
        [
            "benchmark",
            "build-release-artifacts",
            "--submission",
            str(submission_path),
            "--conflicts-declaration",
            "no-known-material-conflicts",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert sorted(path.name for path in output.iterdir()) == [
        "conflicts-disclosure.json",
        "correction-policy.json",
        "protocol-freeze.json",
        "technical-report.json",
    ]
    assert all(path.read_bytes().endswith(b"\n") for path in output.iterdir())


def test_cli_rejects_contradictory_conflict_declaration_without_partial_output(
    tmp_path: Path,
) -> None:
    submission_path = tmp_path / "draft-submission.json"
    submission_path.write_text(
        _submission(ReleaseEvidenceRecord()).model_dump_json(),
        encoding="utf-8",
    )
    output = tmp_path / "release-artifacts"
    result = CliRunner().invoke(
        main,
        [
            "benchmark",
            "build-release-artifacts",
            "--submission",
            str(submission_path),
            "--conflicts-declaration",
            "no-known-material-conflicts",
            "--conflict",
            "advisory",
            "Example Provider",
            "The signer held a paid advisory relationship during the covered release period.",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code != 0
    assert "release artifact construction failed" in result.output
    assert not output.exists()


def test_cli_stage_two_reuses_persisted_gate_output_without_rerunning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    package = tmp_path / "private-preparation"
    record = tmp_path / "release-evidence-record.json"
    statement = tmp_path / "release-evidence-statement.json"
    submission = tmp_path / "submission.json"
    gate_executions = 0

    def controlled_gate(
        _argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str],
    ) -> MasterGateExecution:
        nonlocal gate_executions
        del cwd, environment
        gate_executions += 1
        return MasterGateExecution(
            returncode=0,
            output=f"private gate execution {gate_executions}\n".encode(),
        )

    monkeypatch.setattr(
        release_evidence_module,
        "_run_master_gate_subprocess",
        controlled_gate,
    )
    monkeypatch.setattr(
        release_evidence_module,
        "_executable_receipt",
        _executable_receipt,
    )
    monkeypatch.setattr(
        release_evidence_module,
        "_tool_distribution_receipts",
        lambda _python: _distribution_receipts(),
    )
    first = CliRunner().invoke(
        main,
        [
            "benchmark",
            "build-release-evidence-record",
            *_artifact_options(repository, commit, artifacts, include_toolchain=True),
            "--preparation-package",
            str(package),
            "--output",
            str(record),
        ],
    )

    assert first.exit_code == 0, first.output
    assert gate_executions == 1
    assert package.is_dir()
    assert record.is_file()
    _write_submission(submission, record)

    def forbidden_prepare(**_kwargs: Any) -> object:
        pytest.fail("statement stage must not execute or prepare the master gate")

    monkeypatch.setattr(
        cli_module,
        "_prepare_release_evidence_from_cli",
        forbidden_prepare,
    )
    second = CliRunner().invoke(
        main,
        [
            "benchmark",
            "build-release-evidence-statement",
            "--submission",
            str(submission),
            "--signer-identity",
            _SIGNER_IDENTITY,
            *_artifact_options(repository, commit, artifacts),
            "--preparation-package",
            str(package),
            "--output",
            str(statement),
        ],
    )

    assert second.exit_code == 0, second.output
    assert gate_executions == 1
    payload = json.loads(statement.read_text(encoding="utf-8"))
    assert payload["release_evidence"] == json.loads(record.read_text(encoding="utf-8"))
    private_output = (package / "master-gate-output.bin").read_bytes().decode().strip()
    assert private_output not in second.output
    assert private_output not in statement.read_text(encoding="utf-8")


def test_cli_stage_two_rejects_partial_package_without_path_or_output_disclosure(
    tmp_path: Path,
) -> None:
    repository, commit = _repository(tmp_path)
    artifacts = _artifacts(tmp_path)
    package = tmp_path / "sensitive-private-preparation"
    package.mkdir()
    (package / "master-gate-output.bin").write_text(
        "secret gate output at /private/sensitive/location\n",
        encoding="utf-8",
    )
    record = ReleaseEvidenceRecord(
        protocol_freeze_receipt_sha256="1" * 64,
        master_gate_receipt_sha256="2" * 64,
        technical_report_sha256="3" * 64,
        correction_policy_sha256="4" * 64,
        conflicts_disclosure_sha256="5" * 64,
        comparative_release=False,
        vendor_rerun_receipt_sha256=None,
    )
    submission = tmp_path / "submission.json"
    candidate = BenchmarkReleaseSubmission(
        protocol=compiled_benchmark_protocol(),
        corpus=SealedCorpusRecord(
            corpus_version=_CORPUS_VERSION,
            corpus_hash=_CORPUS_HASH,
            scenarios=(),
        ),
        baselines=(),
        pilot=PilotEvidenceRecord(),
        conformance_environments=(),
        cross_machine_reproduction=None,
        release_evidence=record,
        human_approval=None,
    )
    submission.write_text(candidate.model_dump_json(), encoding="utf-8")
    statement = tmp_path / "statement.json"

    result = CliRunner().invoke(
        main,
        [
            "benchmark",
            "build-release-evidence-statement",
            "--submission",
            str(submission),
            "--signer-identity",
            _SIGNER_IDENTITY,
            *_artifact_options(repository, commit, artifacts),
            "--preparation-package",
            str(package),
            "--output",
            str(statement),
        ],
    )

    assert result.exit_code != 0
    assert "release evidence statement construction failed" in result.output
    assert str(package) not in result.output
    assert "secret gate output" not in result.output
    assert "/private/sensitive/location" not in result.output
    assert not statement.exists()


def _executable_receipt(
    name: str,
    _executable: Path,
    _version_arguments: tuple[str, ...],
) -> MasterGateExecutableReceipt:
    """Return one deterministic executable receipt at the private probe seam."""
    import hashlib

    return MasterGateExecutableReceipt(
        name=name,
        sha256=hashlib.sha256(name.encode()).hexdigest(),
        version=f"{name} test-version",
    )


def _distribution_receipts() -> tuple[MasterGateDistributionReceipt, ...]:
    """Return the complete deterministic test tool inventory."""
    import hashlib

    return tuple(
        MasterGateDistributionReceipt(
            name=name,
            version="1.0.0",
            file_inventory_sha256=hashlib.sha256(name.encode()).hexdigest(),
            file_count=1,
        )
        for name in ("coverage", "mypy", "pytest", "pytest-cov", "ruff")
    )
