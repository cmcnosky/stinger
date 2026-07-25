"""Artifact-derived conformance evidence and trust-binding tests."""

from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from pydantic import BaseModel

import stinger.benchmark.conformance as conformance_module
import stinger.benchmark.gates as gates_module
import stinger.benchmark.machine_environment as machine_module
from stinger.benchmark.conformance import (
    CONFORMANCE_WORKFLOW_INPUT_FILE,
    CONFORMANCE_WORKFLOW_OUTPUT_FILE,
    CONFORMANCE_WORKFLOW_RECEIPT_FILE,
    ConformanceBuilderError,
    ConformanceWorkflowInput,
    ConformanceWorkflowReceipt,
    build_conformance_environment_record,
    build_conformance_environment_statement,
    prepare_conformance_workflow,
    write_conformance_environment_record,
    write_conformance_environment_statement,
    write_conformance_workflow_package,
)
from stinger.benchmark.gates import (
    ConformanceArchitecture,
    ConformanceEnvironmentRecord,
    ConformanceEnvironmentStatement,
    ConformancePlatform,
    VerifiedConformanceAuthorization,
    authorize_conformance_statement,
    compiled_benchmark_protocol,
)
from stinger.benchmark.machine_environment import (
    MachineArchitecture,
    MachineIdentitySource,
    MachinePlatform,
    MachineWorkflowEvidencePaths,
    VerifiedMachineWorkflowAttestation,
    build_machine_workflow_attestation,
    create_machine_environment_identity_artifact,
    sign_machine_workflow_attestation,
    write_machine_workflow_attestation,
)
from stinger.benchmark.release_evidence import (
    MasterGateDistributionReceipt,
    MasterGateExecutableReceipt,
    MasterGateWorkflowReceipt,
)
from stinger.benchmark.signing import (
    CONFORMANCE_SIGNATURE_NAMESPACE,
    sign_conformance_statement,
)

IDENTITY = "conformance@example.test"
CORPUS_HASH = "a" * 64


@pytest.fixture
def clean_repository(tmp_path: Path) -> Path:
    """Create one exact committed Git checkout for conformance probes."""
    repository = tmp_path / "repository"
    repository.mkdir()
    _run(["git", "init", "-q", str(repository)])
    _run(["git", "-C", str(repository), "config", "user.name", "Stinger Test"])
    _run(
        [
            "git",
            "-C",
            str(repository),
            "config",
            "user.email",
            "stinger-test@example.test",
        ]
    )
    (repository / "tracked.txt").write_text("committed\n", encoding="utf-8")
    _run(["git", "-C", str(repository), "add", "tracked.txt"])
    _run(["git", "-C", str(repository), "commit", "-q", "-m", "test fixture"])
    return repository


@pytest.fixture
def signed_conformance_artifacts(
    tmp_path: Path,
    clean_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Path]:
    """Create exact workflow artifacts and a signed synthetic host observation."""
    observation = machine_module._ObservedHostIdentity(
        platform=MachinePlatform.MACOS,
        architecture=MachineArchitecture.ARM64,
        identity_source=MachineIdentitySource.MACOS_IOPLATFORM_UUID,
        canonical_identifier="12345678-1234-4234-9234-123456789abc",
    )
    monkeypatch.setattr(machine_module, "_observe_host_identity", lambda: observation)
    artifacts = {
        "workflow_input": tmp_path / "workflow-input.json",
        "workflow_output": tmp_path / "workflow-output.inventory.json",
        "workflow_raw_output": tmp_path / "workflow-output.bin",
        "machine_identity": tmp_path / "machine-environment.json",
        "machine_attestation": tmp_path / "machine-workflow-attestation.json",
    }
    commit = _git_head(clean_repository)
    raw_output = b"fixed public conformance workflow passed\n"
    workflow_input = ConformanceWorkflowInput(
        benchmark_protocol_version=compiled_benchmark_protocol().benchmark_protocol_version,
        rubric_version=compiled_benchmark_protocol().rubric_version,
        corpus_hash=CORPUS_HASH,
        stinger_commit=commit,
    )
    input_bytes = _canonical_model_bytes(workflow_input)
    master_gate = _master_gate_receipt(commit, raw_output)
    workflow_receipt = ConformanceWorkflowReceipt(
        workflow_input_sha256=hashlib.sha256(input_bytes).hexdigest(),
        master_gate=master_gate,
    )
    artifacts["workflow_input"].write_bytes(input_bytes)
    artifacts["workflow_output"].write_bytes(_canonical_model_bytes(workflow_receipt))
    artifacts["workflow_raw_output"].write_bytes(raw_output)
    create_machine_environment_identity_artifact(artifacts["machine_identity"])
    private_key, allowed_signers = _signing_material(
        tmp_path,
        "machine-workflow",
        IDENTITY,
    )
    attestation = build_machine_workflow_attestation(
        machine_identity_artifact=artifacts["machine_identity"],
        workflow_input=artifacts["workflow_input"],
        workflow_receipt=artifacts["workflow_output"],
        repository=clean_repository,
        expected_stinger_commit=commit,
        signer_identity=IDENTITY,
    )
    write_machine_workflow_attestation(
        artifacts["machine_attestation"],
        attestation,
    )
    artifacts["machine_signature"] = sign_machine_workflow_attestation(
        artifacts["machine_attestation"],
        private_key,
    )
    artifacts["machine_allowed_signers"] = allowed_signers
    return artifacts


def test_statement_fields_are_derived_from_exact_local_artifacts(
    clean_repository: Path,
    signed_conformance_artifacts: dict[str, Path],
) -> None:
    """The statement binds observed versions, Git HEAD, and exact artifact bytes."""
    artifacts = signed_conformance_artifacts
    statement = _build_statement(clean_repository, artifacts)
    protocol = compiled_benchmark_protocol()

    assert statement.environment_id == "environment-one"
    assert statement.signer_identity == IDENTITY
    assert statement.platform is ConformancePlatform.MACOS
    assert statement.architecture is ConformanceArchitecture.ARM64
    assert statement.stinger_commit == _git_head(clean_repository)
    assert statement.benchmark_protocol_version == protocol.benchmark_protocol_version
    assert statement.rubric_version == protocol.rubric_version
    assert statement.corpus_hash == CORPUS_HASH
    assert statement.environment_fingerprint_sha256 == _file_sha256(artifacts["machine_identity"])
    assert statement.workflow_input_sha256 == _file_sha256(artifacts["workflow_input"])
    assert statement.workflow_output_inventory_sha256 == _file_sha256(artifacts["workflow_output"])


def test_fixed_workflow_preparation_writes_exact_create_only_package(
    tmp_path: Path,
    clean_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The supported workflow path fixes the command and preserves its exact output."""
    commit = _git_head(clean_repository)
    output = b"fixed conformance gate output\n"
    master_gate = _master_gate_receipt(commit, output)
    monkeypatch.setattr(
        conformance_module,
        "run_tracked_master_gate_workflow",
        lambda _repository, **_kwargs: (master_gate, output),
    )

    prepared = prepare_conformance_workflow(
        repository=clean_repository,
        toolchain_python=tmp_path / "explicit-python",
        expected_stinger_commit=commit,
        corpus_hash=CORPUS_HASH,
    )
    package = tmp_path / "conformance-package"
    write_conformance_workflow_package(package, prepared)

    assert {path.name for path in package.iterdir()} == {
        CONFORMANCE_WORKFLOW_INPUT_FILE,
        CONFORMANCE_WORKFLOW_RECEIPT_FILE,
        CONFORMANCE_WORKFLOW_OUTPUT_FILE,
    }
    assert (package / CONFORMANCE_WORKFLOW_OUTPUT_FILE).read_bytes() == output
    assert package.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in package.iterdir())
    with pytest.raises(ConformanceBuilderError, match="already exists"):
        write_conformance_workflow_package(package, prepared)


def test_statement_rejects_arbitrary_machine_prose_and_workflow_mutation(
    tmp_path: Path,
    clean_repository: Path,
    signed_conformance_artifacts: dict[str, Path],
) -> None:
    """Caller prose and post-signature workflow changes cannot become conformance evidence."""
    prose = tmp_path / "machine-prose.txt"
    prose.write_text("trust me, this is another machine\n", encoding="utf-8")
    prose_artifacts = {
        **signed_conformance_artifacts,
        "machine_identity": prose,
    }
    with pytest.raises(
        ConformanceBuilderError,
        match="signed machine workflow evidence failed verification",
    ):
        _build_statement(clean_repository, prose_artifacts)

    signed_conformance_artifacts["workflow_output"].write_bytes(b'{"outputs":["changed"]}\n')
    with pytest.raises(
        ConformanceBuilderError,
        match="conformance workflow receipt is invalid",
    ):
        _build_statement(clean_repository, signed_conformance_artifacts)


def test_statement_rejects_output_substitution(
    clean_repository: Path,
    signed_conformance_artifacts: dict[str, Path],
) -> None:
    """A typed favorable receipt cannot be paired with different raw workflow output."""
    signed_conformance_artifacts["workflow_raw_output"].write_bytes(b"different workflow output\n")

    with pytest.raises(
        ConformanceBuilderError,
        match="not exactly cross-bound",
    ):
        _build_statement(clean_repository, signed_conformance_artifacts)


def test_statement_uses_one_retained_workflow_snapshot_during_attestation(
    clean_repository: Path,
    signed_conformance_artifacts: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Timed A→B→A swaps cannot change the bytes the attestation verifies."""
    artifacts = signed_conformance_artifacts
    original_verify = conformance_module.verify_machine_workflow_attestation

    def verify_after_swap(
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
        assert workflow_input != artifacts["workflow_input"]
        assert workflow_receipt != artifacts["workflow_output"]
        originals = {
            path: path.read_bytes()
            for path in (
                artifacts["workflow_input"],
                artifacts["workflow_output"],
                artifacts["workflow_raw_output"],
            )
        }
        try:
            artifacts["workflow_input"].write_bytes(b'{"substituted":"input"}\n')
            artifacts["workflow_output"].write_bytes(b'{"substituted":"receipt"}\n')
            artifacts["workflow_raw_output"].write_bytes(b"substituted output\n")
            return original_verify(
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
            for path, content in originals.items():
                path.write_bytes(content)

    monkeypatch.setattr(
        conformance_module,
        "verify_machine_workflow_attestation",
        verify_after_swap,
    )

    statement = _build_statement(clean_repository, artifacts)

    assert statement.workflow_input_sha256 == _file_sha256(artifacts["workflow_input"])
    assert statement.workflow_output_inventory_sha256 == _file_sha256(artifacts["workflow_output"])


def test_statement_rejects_untrusted_machine_workflow_signature(
    tmp_path: Path,
    clean_repository: Path,
    signed_conformance_artifacts: dict[str, Path],
) -> None:
    """A signature is insufficient without the matching independently supplied trust file."""
    _, wrong_trust = _signing_material(tmp_path, "wrong-machine", IDENTITY)
    artifacts = {
        **signed_conformance_artifacts,
        "machine_allowed_signers": wrong_trust,
    }

    with pytest.raises(
        ConformanceBuilderError,
        match="signed machine workflow evidence failed verification",
    ):
        _build_statement(clean_repository, artifacts)


@pytest.mark.parametrize("dirty_kind", ["tracked", "untracked"])
def test_statement_builder_rejects_dirty_git_checkout(
    clean_repository: Path,
    signed_conformance_artifacts: dict[str, Path],
    dirty_kind: str,
) -> None:
    """Both tracked modifications and untracked files make conformance fail closed."""
    if dirty_kind == "tracked":
        (clean_repository / "tracked.txt").write_text("modified\n", encoding="utf-8")
    else:
        (clean_repository / "untracked.txt").write_text("untracked\n", encoding="utf-8")

    with pytest.raises(
        ConformanceBuilderError,
        match="checkout must be clean at an exact commit",
    ):
        _build_statement(clean_repository, signed_conformance_artifacts)


def test_conformance_git_identity_ignores_path_shim_and_repository_redirect(
    tmp_path: Path,
    clean_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ambient Git executable and routing variables cannot bless a dirty checkout."""
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    _run(["/usr/bin/git", "init", "-q", str(decoy)])
    _run(["/usr/bin/git", "-C", str(decoy), "config", "user.name", "Stinger Test"])
    _run(
        [
            "/usr/bin/git",
            "-C",
            str(decoy),
            "config",
            "user.email",
            "stinger-test@example.test",
        ]
    )
    (decoy / "tracked.txt").write_text("committed\n", encoding="utf-8")
    _run(["/usr/bin/git", "-C", str(decoy), "add", "tracked.txt"])
    _run(["/usr/bin/git", "-C", str(decoy), "commit", "-q", "-m", "fixture"])
    (clean_repository / "tracked.txt").write_text("dirty\n", encoding="utf-8")

    shim_directory = tmp_path / "shim"
    shim_directory.mkdir()
    marker = tmp_path / "shim-was-called"
    shim = shim_directory / "git"
    shim.write_text(
        f"#!/bin/sh\n/usr/bin/touch {shlex.quote(str(marker))}\nexit 0\n",
        encoding="utf-8",
    )
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", str(shim_directory))
    monkeypatch.setenv("GIT_DIR", str(decoy / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(decoy))

    with pytest.raises(ConformanceBuilderError, match="checkout must be clean"):
        conformance_module._clean_git_head(clean_repository)
    assert not marker.exists()


def test_statement_writer_is_atomic_and_never_overwrites(
    tmp_path: Path,
    clean_repository: Path,
    signed_conformance_artifacts: dict[str, Path],
) -> None:
    """A second publication attempt cannot replace an existing statement."""
    statement = _build_statement(clean_repository, signed_conformance_artifacts)
    destination = tmp_path / "published" / "conformance-statement.json"
    write_conformance_environment_statement(destination, statement)
    original = destination.read_bytes()

    with pytest.raises(ConformanceBuilderError, match="output already exists"):
        write_conformance_environment_statement(
            destination,
            statement.model_copy(update={"environment_id": "environment-two"}),
        )

    assert destination.read_bytes() == original
    assert original.endswith(b"\n")


def test_real_ssh_signature_authorizes_and_derives_record(
    tmp_path: Path,
    clean_repository: Path,
    signed_conformance_artifacts: dict[str, Path],
) -> None:
    """A trusted real SSH signature produces a gate-valid derived record."""
    statement = _build_statement(clean_repository, signed_conformance_artifacts)
    statement_path = tmp_path / "conformance-statement.json"
    write_conformance_environment_statement(statement_path, statement)
    private_key, allowed_signers = _signing_material(tmp_path, "trusted", IDENTITY)
    signature = sign_conformance_statement(statement_path, private_key)

    authorization = authorize_conformance_statement(
        statement_path,
        signature,
        allowed_signers,
        IDENTITY,
    )
    record = build_conformance_environment_record(
        statement_path,
        signature,
        allowed_signers,
        IDENTITY,
    )

    assert authorization.statement == statement
    assert authorization.identity == IDENTITY
    assert authorization.namespace == CONFORMANCE_SIGNATURE_NAMESPACE
    assert authorization.signing_key_fingerprint.startswith("SHA256:")
    _assert_record_matches_authorization(record, authorization)
    assert gates_module._valid_conformance_environment(record, authorization)

    record_path = tmp_path / "conformance-record.json"
    write_conformance_environment_record(record_path, record)
    original = record_path.read_bytes()
    with pytest.raises(ConformanceBuilderError, match="output already exists"):
        write_conformance_environment_record(
            record_path,
            record.model_copy(update={"environment_id": "environment-two"}),
        )
    assert record_path.read_bytes() == original


def test_record_builder_rejects_tampering_and_wrong_trust(
    tmp_path: Path,
    clean_repository: Path,
    signed_conformance_artifacts: dict[str, Path],
) -> None:
    """Changed statement bytes or a different trust policy cannot yield a record."""
    statement = _build_statement(clean_repository, signed_conformance_artifacts)
    statement_path = tmp_path / "conformance-statement.json"
    write_conformance_environment_statement(statement_path, statement)
    original = statement_path.read_bytes()
    private_key, allowed_signers = _signing_material(tmp_path, "trusted", IDENTITY)
    signature = sign_conformance_statement(statement_path, private_key)
    _, wrong_allowed_signers = _signing_material(tmp_path, "wrong", IDENTITY)

    statement_path.write_bytes(original.replace(b"environment-one", b"environment-other"))
    with pytest.raises(
        ConformanceBuilderError,
        match="statement authorization failed",
    ):
        build_conformance_environment_record(
            statement_path,
            signature,
            allowed_signers,
            IDENTITY,
        )

    statement_path.write_bytes(original)
    with pytest.raises(
        ConformanceBuilderError,
        match="statement authorization failed",
    ):
        build_conformance_environment_record(
            statement_path,
            signature,
            wrong_allowed_signers,
            IDENTITY,
        )


def test_gate_binding_rejects_missing_or_altered_authorization(
    tmp_path: Path,
    clean_repository: Path,
    signed_conformance_artifacts: dict[str, Path],
) -> None:
    """A record alone, or an authorization changed after verification, is insufficient."""
    statement = _build_statement(clean_repository, signed_conformance_artifacts)
    statement_path = tmp_path / "conformance-statement.json"
    write_conformance_environment_statement(statement_path, statement)
    private_key, allowed_signers = _signing_material(tmp_path, "trusted", IDENTITY)
    signature = sign_conformance_statement(statement_path, private_key)
    authorization = authorize_conformance_statement(
        statement_path,
        signature,
        allowed_signers,
        IDENTITY,
    )
    record = build_conformance_environment_record(
        statement_path,
        signature,
        allowed_signers,
        IDENTITY,
    )
    altered = replace(authorization, identity="different@example.test")

    assert not gates_module._valid_conformance_environment(record, None)
    assert not gates_module._valid_conformance_environment(record, altered)


def _build_statement(
    repository: Path,
    artifacts: dict[str, Path],
) -> ConformanceEnvironmentStatement:
    """Build the standard statement used by focused conformance tests."""
    return build_conformance_environment_statement(
        "environment-one",
        corpus_hash=CORPUS_HASH,
        workflow_input=artifacts["workflow_input"],
        workflow_output_inventory=artifacts["workflow_output"],
        workflow_output=artifacts["workflow_raw_output"],
        machine_workflow_evidence=MachineWorkflowEvidencePaths(
            identity_artifact=artifacts["machine_identity"],
            attestation=artifacts["machine_attestation"],
            signature=artifacts["machine_signature"],
            allowed_signers=artifacts["machine_allowed_signers"],
            signer_identity=IDENTITY,
        ),
        repository=repository,
        signer_identity=IDENTITY,
    )


def _signing_material(
    root: Path,
    label: str,
    identity: str,
) -> tuple[Path, Path]:
    """Generate one ephemeral Ed25519 key and independent allowed-signers policy."""
    private_key = root / f"{label}-key"
    _run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            f"stinger-{label}-test-only",
            "-f",
            str(private_key),
        ]
    )
    public_key = private_key.with_suffix(".pub").read_text(encoding="utf-8").strip()
    allowed_signers = root / f"{label}-allowed-signers"
    allowed_signers.write_text(f"{identity} {public_key}\n", encoding="utf-8")
    return private_key, allowed_signers


def _assert_record_matches_authorization(
    record: ConformanceEnvironmentRecord,
    authorization: VerifiedConformanceAuthorization,
) -> None:
    """Assert all record trust fields were derived from verified exact bytes."""
    statement = authorization.statement
    assert record.environment_id == statement.environment_id
    assert record.platform is statement.platform
    assert record.architecture is statement.architecture
    assert record.python_version == statement.python_version
    assert record.stinger_commit == statement.stinger_commit
    assert record.benchmark_protocol_version == statement.benchmark_protocol_version
    assert record.rubric_version == statement.rubric_version
    assert record.corpus_hash == statement.corpus_hash
    assert record.environment_fingerprint_sha256 == (statement.environment_fingerprint_sha256)
    assert record.workflow_input_sha256 == statement.workflow_input_sha256
    assert record.workflow_receipt_sha256 == statement.workflow_output_inventory_sha256
    assert record.receipt_signature_sha256 == authorization.signature_sha256
    assert record.allowed_signers_sha256 == authorization.allowed_signers_sha256
    assert record.signer_identity == authorization.identity


def _file_sha256(path: Path) -> str:
    """Hash exact fixture bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_model_bytes(model: BaseModel) -> bytes:
    """Serialize one fixture model in the production canonical form."""
    return (
        json.dumps(
            model.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


def _master_gate_receipt(commit: str, output: bytes) -> MasterGateWorkflowReceipt:
    """Build one exact typed fixed-gate receipt without running the full project gate."""
    executable_names = ("bash", "git", "grep", "python")
    distributions = ("coverage", "mypy", "pytest", "pytest-cov", "ruff")
    return MasterGateWorkflowReceipt(
        stinger_commit=commit,
        source_archive_sha256="1" * 64,
        check_script_sha256="2" * 64,
        command=("bash", "scripts/check.sh"),
        environment_projection=(
            "COVERAGE_FILE=external-artifact",
            "HOME=ephemeral-empty",
            "LANG=C",
            "LC_ALL=C",
            "MYPY_CACHE_DIR=external-artifact",
            "PATH=fixed-system-search-v1",
            "PYTEST_ADDOPTS=-p no:cacheprovider",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONPATH=tracked-snapshot/src",
            "RUFF_CACHE_DIR=external-artifact",
            "STINGER_CHECK_ARTIFACT_DIR=external-artifact",
            "STINGER_CHECK_PYTHON=external-toolchain-python",
            "STINGER_COVERAGE_JSON=external-artifact/coverage.json",
            "TMPDIR=external-artifact",
        ),
        executables=tuple(
            MasterGateExecutableReceipt(
                name=name,
                sha256=hashlib.sha256(name.encode()).hexdigest(),
                version=f"{name} test-version",
            )
            for name in executable_names
        ),
        distributions=tuple(
            MasterGateDistributionReceipt(
                name=name,
                version="1.0.0",
                file_inventory_sha256=hashlib.sha256(name.encode()).hexdigest(),
                file_count=1,
            )
            for name in distributions
        ),
        returncode=0,
        output_sha256=hashlib.sha256(output).hexdigest(),
        output_size_bytes=len(output),
    )


def _git_head(repository: Path) -> str:
    """Read the exact fixture commit."""
    return _run(["git", "-C", str(repository), "rev-parse", "--verify", "HEAD"]).stdout.strip()


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """Run one local fixture command and fail with captured diagnostics."""
    return subprocess.run(
        argv,
        capture_output=True,
        check=True,
        text=True,
    )
