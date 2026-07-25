"""Host-derived environment identity and signed workflow provenance tests."""

from __future__ import annotations

import hashlib
import json
import shlex
import stat
import subprocess
from pathlib import Path

import pytest

import stinger.benchmark.machine_environment as machine_module
from stinger.benchmark.machine_environment import (
    MACHINE_ENVIRONMENT_CLAIM_BOUNDARY,
    MACHINE_WORKFLOW_SIGNATURE_NAMESPACE,
    MachineArchitecture,
    MachineAttestationError,
    MachineEnvironmentIdentity,
    MachineIdentitySource,
    MachinePlatform,
    build_machine_environment_identity,
    build_machine_workflow_attestation,
    create_machine_environment_identity_artifact,
    load_machine_environment_identity,
    machine_environment_identity_sha256,
    sign_machine_workflow_attestation,
    verify_local_machine_environment_identity,
    verify_machine_workflow_attestation,
    write_machine_workflow_attestation,
)
from stinger.benchmark.signing import sign_protocol

SIGNER_IDENTITY = "machine-workflow@example.test"
RAW_MACOS_ID = "12345678-1234-4234-9234-123456789abc"
OTHER_RAW_MACOS_ID = "87654321-4321-4234-9234-cba987654321"


@pytest.fixture
def clean_repository(tmp_path: Path) -> Path:
    """Create one exact clean Git checkout for workflow provenance."""
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
def signing_material(tmp_path: Path) -> dict[str, Path]:
    """Generate an ephemeral Ed25519 key and external trust policy."""
    private_key = tmp_path / "machine-key"
    generated = subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "stinger-machine-test-only",
            "-f",
            str(private_key),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    if generated.returncode != 0:
        pytest.fail(f"could not generate test signing key: {generated.stderr}")
    public_key = private_key.with_suffix(".pub").read_text(encoding="utf-8").strip()
    allowed_signers = tmp_path / "allowed_signers"
    allowed_signers.write_text(f"{SIGNER_IDENTITY} {public_key}\n", encoding="utf-8")
    return {
        "private_key": private_key,
        "allowed_signers": allowed_signers,
    }


@pytest.fixture
def observed_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the real host probe with one deterministic macOS observation."""
    _patch_observation(monkeypatch, RAW_MACOS_ID)


@pytest.fixture
def identity_artifact(
    tmp_path: Path,
    observed_macos: None,
) -> Path:
    """Create one locally verified canonical identity artifact."""
    del observed_macos
    destination = tmp_path / "machine-environment.json"
    create_machine_environment_identity_artifact(destination)
    return destination


@pytest.fixture
def workflow_artifacts(tmp_path: Path) -> dict[str, Path]:
    """Create distinct nonempty workflow input and receipt artifacts."""
    workflow_input = tmp_path / "workflow-input.json"
    workflow_receipt = tmp_path / "workflow-receipt.json"
    workflow_input.write_bytes(b'{"workflow":"baseline-v2"}\n')
    workflow_receipt.write_bytes(b'{"master_gate":"passed"}\n')
    return {
        "input": workflow_input,
        "receipt": workflow_receipt,
    }


def test_identity_is_stable_application_scoped_and_does_not_emit_raw_host_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same observation is stable while raw host identity never enters the artifact."""
    _patch_observation(monkeypatch, RAW_MACOS_ID)
    first = build_machine_environment_identity()
    first_path = tmp_path / "first.json"
    create_machine_environment_identity_artifact(first_path)
    second = load_machine_environment_identity(first_path)

    assert first == second
    assert first.claim_boundary == MACHINE_ENVIRONMENT_CLAIM_BOUNDARY
    assert first.platform is MachinePlatform.MACOS
    assert first.architecture is MachineArchitecture.ARM64
    assert first.identity_source is MachineIdentitySource.MACOS_IOPLATFORM_UUID
    assert RAW_MACOS_ID.encode("ascii") not in first_path.read_bytes()
    assert hashlib.sha256(
        first_path.read_bytes()
    ).hexdigest() == machine_environment_identity_sha256(first)
    assert stat.S_IMODE(first_path.stat().st_mode) == 0o600

    _patch_observation(monkeypatch, OTHER_RAW_MACOS_ID)
    assert (
        build_machine_environment_identity().host_identity_commitment_sha256
        != first.host_identity_commitment_sha256
    )


def test_local_verification_rejects_an_identity_from_another_environment(
    identity_artifact: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A canonical but different host artifact cannot be used as the local identity."""
    _patch_observation(monkeypatch, OTHER_RAW_MACOS_ID)

    with pytest.raises(MachineAttestationError, match="current host observation"):
        verify_local_machine_environment_identity(identity_artifact)


def test_workflow_attestation_binds_clean_commit_identity_and_exact_bytes(
    clean_repository: Path,
    identity_artifact: Path,
    workflow_artifacts: dict[str, Path],
) -> None:
    """Construction re-observes the host and binds exact workflow provenance."""
    commit = _git_head(clean_repository)
    statement = build_machine_workflow_attestation(
        machine_identity_artifact=identity_artifact,
        workflow_input=workflow_artifacts["input"],
        workflow_receipt=workflow_artifacts["receipt"],
        repository=clean_repository,
        expected_stinger_commit=commit,
        signer_identity=SIGNER_IDENTITY,
    )
    identity = load_machine_environment_identity(identity_artifact)

    assert statement.machine_identity_sha256 == machine_environment_identity_sha256(identity)
    assert statement.host_identity_commitment_sha256 == identity.host_identity_commitment_sha256
    assert statement.stinger_commit == commit
    assert statement.workflow_input_sha256 == _file_sha256(workflow_artifacts["input"])
    assert statement.workflow_receipt_sha256 == _file_sha256(workflow_artifacts["receipt"])
    assert statement.signer_identity == SIGNER_IDENTITY


def test_workflow_input_and_receipt_must_be_distinct(
    clean_repository: Path,
    identity_artifact: Path,
    workflow_artifacts: dict[str, Path],
) -> None:
    """One file cannot self-attest as both workflow request and execution receipt."""
    with pytest.raises(MachineAttestationError, match="must be distinct"):
        build_machine_workflow_attestation(
            machine_identity_artifact=identity_artifact,
            workflow_input=workflow_artifacts["input"],
            workflow_receipt=workflow_artifacts["input"],
            repository=clean_repository,
            expected_stinger_commit=_git_head(clean_repository),
            signer_identity=SIGNER_IDENTITY,
        )


def test_signed_workflow_verification_uses_dedicated_namespace_and_external_trust(
    tmp_path: Path,
    clean_repository: Path,
    identity_artifact: Path,
    workflow_artifacts: dict[str, Path],
    signing_material: dict[str, Path],
) -> None:
    """A trusted key covers the canonical attestation and every supplied binding."""
    commit = _git_head(clean_repository)
    statement = build_machine_workflow_attestation(
        machine_identity_artifact=identity_artifact,
        workflow_input=workflow_artifacts["input"],
        workflow_receipt=workflow_artifacts["receipt"],
        repository=clean_repository,
        expected_stinger_commit=commit,
        signer_identity=SIGNER_IDENTITY,
    )
    attestation_path = tmp_path / "workflow-attestation.json"
    write_machine_workflow_attestation(attestation_path, statement)
    signature = sign_machine_workflow_attestation(
        attestation_path,
        signing_material["private_key"],
    )

    verified = verify_machine_workflow_attestation(
        machine_identity_artifact=identity_artifact,
        workflow_input=workflow_artifacts["input"],
        workflow_receipt=workflow_artifacts["receipt"],
        attestation=attestation_path,
        signature=signature,
        allowed_signers=signing_material["allowed_signers"],
        signer_identity=SIGNER_IDENTITY,
        expected_stinger_commit=commit,
    )

    assert verified.statement == statement
    assert verified.signature_namespace == MACHINE_WORKFLOW_SIGNATURE_NAMESPACE
    assert verified.attestation_sha256 == _file_sha256(attestation_path)
    assert verified.signature_sha256 == _file_sha256(signature)
    assert verified.allowed_signers_sha256 == _file_sha256(signing_material["allowed_signers"])
    assert verified.signing_key_fingerprint.startswith("SHA256:")


@pytest.mark.parametrize("artifact", ["input", "receipt"])
def test_verification_fails_closed_when_bound_workflow_bytes_change(
    tmp_path: Path,
    clean_repository: Path,
    identity_artifact: Path,
    workflow_artifacts: dict[str, Path],
    signing_material: dict[str, Path],
    artifact: str,
) -> None:
    """Changing either workflow side after signing invalidates provenance."""
    commit = _git_head(clean_repository)
    statement = build_machine_workflow_attestation(
        machine_identity_artifact=identity_artifact,
        workflow_input=workflow_artifacts["input"],
        workflow_receipt=workflow_artifacts["receipt"],
        repository=clean_repository,
        expected_stinger_commit=commit,
        signer_identity=SIGNER_IDENTITY,
    )
    attestation_path = tmp_path / "workflow-attestation.json"
    write_machine_workflow_attestation(attestation_path, statement)
    signature = sign_machine_workflow_attestation(
        attestation_path,
        signing_material["private_key"],
    )
    workflow_artifacts[artifact].write_bytes(b'{"tampered":true}\n')

    with pytest.raises(MachineAttestationError, match=f"workflow {artifact}"):
        verify_machine_workflow_attestation(
            machine_identity_artifact=identity_artifact,
            workflow_input=workflow_artifacts["input"],
            workflow_receipt=workflow_artifacts["receipt"],
            attestation=attestation_path,
            signature=signature,
            allowed_signers=signing_material["allowed_signers"],
            signer_identity=SIGNER_IDENTITY,
            expected_stinger_commit=commit,
        )


def test_protocol_namespace_signature_cannot_authorize_machine_workflow(
    tmp_path: Path,
    clean_repository: Path,
    identity_artifact: Path,
    workflow_artifacts: dict[str, Path],
    signing_material: dict[str, Path],
) -> None:
    """The same trusted key in the generic protocol namespace still fails."""
    commit = _git_head(clean_repository)
    statement = build_machine_workflow_attestation(
        machine_identity_artifact=identity_artifact,
        workflow_input=workflow_artifacts["input"],
        workflow_receipt=workflow_artifacts["receipt"],
        repository=clean_repository,
        expected_stinger_commit=commit,
        signer_identity=SIGNER_IDENTITY,
    )
    attestation_path = tmp_path / "wrong-namespace.json"
    write_machine_workflow_attestation(attestation_path, statement)
    wrong_signature = sign_protocol(
        attestation_path,
        signing_material["private_key"],
    )

    with pytest.raises(MachineAttestationError, match="authorization failed"):
        verify_machine_workflow_attestation(
            machine_identity_artifact=identity_artifact,
            workflow_input=workflow_artifacts["input"],
            workflow_receipt=workflow_artifacts["receipt"],
            attestation=attestation_path,
            signature=wrong_signature,
            allowed_signers=signing_material["allowed_signers"],
            signer_identity=SIGNER_IDENTITY,
            expected_stinger_commit=commit,
        )


def test_identity_substitution_after_signing_is_rejected(
    tmp_path: Path,
    clean_repository: Path,
    identity_artifact: Path,
    workflow_artifacts: dict[str, Path],
    signing_material: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A different canonical host artifact cannot be substituted after signing."""
    commit = _git_head(clean_repository)
    statement = build_machine_workflow_attestation(
        machine_identity_artifact=identity_artifact,
        workflow_input=workflow_artifacts["input"],
        workflow_receipt=workflow_artifacts["receipt"],
        repository=clean_repository,
        expected_stinger_commit=commit,
        signer_identity=SIGNER_IDENTITY,
    )
    attestation_path = tmp_path / "workflow-attestation.json"
    write_machine_workflow_attestation(attestation_path, statement)
    signature = sign_machine_workflow_attestation(
        attestation_path,
        signing_material["private_key"],
    )
    _patch_observation(monkeypatch, OTHER_RAW_MACOS_ID)
    substituted = tmp_path / "substituted-identity.json"
    create_machine_environment_identity_artifact(substituted)

    with pytest.raises(MachineAttestationError, match="supplied identity"):
        verify_machine_workflow_attestation(
            machine_identity_artifact=substituted,
            workflow_input=workflow_artifacts["input"],
            workflow_receipt=workflow_artifacts["receipt"],
            attestation=attestation_path,
            signature=signature,
            allowed_signers=signing_material["allowed_signers"],
            signer_identity=SIGNER_IDENTITY,
            expected_stinger_commit=commit,
        )


@pytest.mark.parametrize("dirty_kind", ["tracked", "untracked"])
def test_workflow_attestation_rejects_dirty_checkout(
    clean_repository: Path,
    identity_artifact: Path,
    workflow_artifacts: dict[str, Path],
    dirty_kind: str,
) -> None:
    """Tracked or untracked changes prevent a clean-commit provenance claim."""
    if dirty_kind == "tracked":
        (clean_repository / "tracked.txt").write_text("modified\n", encoding="utf-8")
    else:
        (clean_repository / "untracked.txt").write_text("untracked\n", encoding="utf-8")

    with pytest.raises(MachineAttestationError, match="checkout must be clean"):
        build_machine_workflow_attestation(
            machine_identity_artifact=identity_artifact,
            workflow_input=workflow_artifacts["input"],
            workflow_receipt=workflow_artifacts["receipt"],
            repository=clean_repository,
            expected_stinger_commit=_git_head(clean_repository),
            signer_identity=SIGNER_IDENTITY,
        )


def test_workflow_git_identity_ignores_path_shim_and_ambient_repository_redirect(
    tmp_path: Path,
    clean_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Workflow provenance cannot inherit a fake Git client or alternate checkout."""
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

    with pytest.raises(MachineAttestationError, match="checkout must be clean"):
        machine_module._clean_git_head(clean_repository)
    assert not marker.exists()


def test_identity_loader_rejects_noncanonical_extra_duplicate_and_unsafe_files(
    tmp_path: Path,
    identity_artifact: Path,
) -> None:
    """Only exact closed canonical regular-file evidence is accepted."""
    original = identity_artifact.read_bytes()

    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_bytes(b" " + original)
    with pytest.raises(MachineAttestationError, match="not canonical JSON"):
        load_machine_environment_identity(noncanonical)

    parsed = json.loads(original)
    parsed["unexpected"] = True
    extra = tmp_path / "extra.json"
    extra.write_text(json.dumps(parsed, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(MachineAttestationError, match="not valid closed JSON"):
        load_machine_environment_identity(extra)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_bytes(original[:-2] + b',"platform":"macos"}\n')
    with pytest.raises(MachineAttestationError, match="not valid closed JSON"):
        load_machine_environment_identity(duplicate)

    linked = tmp_path / "identity-link"
    linked.symlink_to(identity_artifact)
    with pytest.raises(MachineAttestationError, match="regular file"):
        load_machine_environment_identity(linked)

    empty = tmp_path / "empty"
    empty.touch()
    with pytest.raises(MachineAttestationError, match="must not be empty"):
        load_machine_environment_identity(empty)


def test_identity_and_attestation_writers_never_overwrite(
    tmp_path: Path,
    observed_macos: None,
) -> None:
    """Identity and workflow publication are create-once operations."""
    del observed_macos
    identity_path = tmp_path / "identity.json"
    create_machine_environment_identity_artifact(identity_path)
    with pytest.raises(MachineAttestationError, match="already exists"):
        create_machine_environment_identity_artifact(identity_path)

    identity = load_machine_environment_identity(identity_path)
    statement = machine_module.MachineWorkflowAttestation(
        machine_identity_sha256=machine_environment_identity_sha256(identity),
        host_identity_commitment_sha256=identity.host_identity_commitment_sha256,
        platform=identity.platform,
        architecture=identity.architecture,
        identity_source=identity.identity_source,
        python_version="3.12.0",
        stinger_commit="a" * 40,
        workflow_input_sha256="b" * 64,
        workflow_receipt_sha256="c" * 64,
        signer_identity=SIGNER_IDENTITY,
    )
    statement_path = tmp_path / "attestation.json"
    write_machine_workflow_attestation(statement_path, statement)
    with pytest.raises(MachineAttestationError, match="already exists"):
        write_machine_workflow_attestation(statement_path, statement)


def test_linux_container_identity_is_rejected_before_machine_id_is_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A container's image-scoped machine-id cannot masquerade as a host identity."""
    monkeypatch.setattr(machine_module, "_observed_platform", lambda: MachinePlatform.LINUX)
    monkeypatch.setattr(
        machine_module,
        "_observed_architecture",
        lambda: MachineArchitecture.X86_64,
    )
    monkeypatch.setattr(machine_module, "_linux_container_observed", lambda: True)

    with pytest.raises(MachineAttestationError, match="container-scoped"):
        build_machine_environment_identity()


def test_linux_machine_id_requires_one_agreeing_canonical_value(tmp_path: Path) -> None:
    """Linux sources may be duplicated only when their exact identities agree."""
    primary = tmp_path / "etc-machine-id"
    compatibility = tmp_path / "dbus-machine-id"
    primary.write_text("1234567890abcdef1234567890ABCDEF\n", encoding="ascii")
    compatibility.write_text("1234567890abcdef1234567890abcdef\n", encoding="ascii")

    assert machine_module._linux_machine_id((primary, compatibility)) == (
        "1234567890abcdef1234567890abcdef"
    )

    compatibility.write_text("abcdef1234567890abcdef1234567890\n", encoding="ascii")
    with pytest.raises(MachineAttestationError, match="missing or ambiguous"):
        machine_module._linux_machine_id((primary, compatibility))

    primary.write_text("00000000000000000000000000000000\n", encoding="ascii")
    with pytest.raises(MachineAttestationError, match="not canonical"):
        machine_module._linux_machine_id((primary,))

    with pytest.raises(MachineAttestationError, match="missing or ambiguous"):
        machine_module._linux_machine_id((tmp_path / "missing",))


def test_windows_machine_guid_requires_one_canonical_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows probing canonicalizes exactly one registry MachineGuid."""
    monkeypatch.setattr(
        machine_module,
        "_fixed_probe_executable",
        lambda _candidates, *, label: Path(r"C:\Windows\System32\reg.exe"),
    )
    output = f"    MachineGuid    REG_SZ    {RAW_MACOS_ID.upper()}\r\n".encode()
    monkeypatch.setattr(machine_module, "_run_probe", lambda _argv, label: output)

    assert machine_module._windows_machine_guid() == RAW_MACOS_ID

    monkeypatch.setattr(machine_module, "_run_probe", lambda _argv, label: b"not a guid")
    with pytest.raises(MachineAttestationError, match="missing or ambiguous"):
        machine_module._windows_machine_guid()


def test_macos_probe_rejects_missing_ambiguous_and_null_uuid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The OS probe fails closed unless it returns one meaningful UUID."""
    monkeypatch.setattr(
        machine_module,
        "_fixed_probe_executable",
        lambda _candidates, *, label: Path("/usr/sbin/ioreg"),
    )

    monkeypatch.setattr(machine_module, "_run_probe", lambda _argv, label: b"no uuid")
    with pytest.raises(MachineAttestationError, match="missing or ambiguous"):
        machine_module._macos_ioplatform_uuid()

    two = (
        f'"IOPlatformUUID" = "{RAW_MACOS_ID}"\n"IOPlatformUUID" = "{OTHER_RAW_MACOS_ID}"\n'
    ).encode()
    monkeypatch.setattr(machine_module, "_run_probe", lambda _argv, label: two)
    with pytest.raises(MachineAttestationError, match="missing or ambiguous"):
        machine_module._macos_ioplatform_uuid()

    null = b'"IOPlatformUUID" = "00000000-0000-0000-0000-000000000000"\n'
    monkeypatch.setattr(machine_module, "_run_probe", lambda _argv, label: null)
    with pytest.raises(MachineAttestationError, match="not canonical"):
        machine_module._macos_ioplatform_uuid()


def test_os_identity_probes_ignore_path_shims(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PATH executables cannot mint a fake macOS or Windows host pseudonym."""
    shim_directory = tmp_path / "shim"
    shim_directory.mkdir()
    markers: list[Path] = []
    for executable in ("ioreg", "reg.exe", "reg"):
        marker = tmp_path / f"{executable}-ran"
        markers.append(marker)
        shim = shim_directory / executable
        shim.write_text(
            "#!/bin/sh\n"
            f"printf ran > '{marker}'\n"
            f'printf \'"IOPlatformUUID" = "{RAW_MACOS_ID}"\\n\'\n'
            f"printf '    MachineGuid    REG_SZ    {RAW_MACOS_ID}\\n'\n",
            encoding="utf-8",
        )
        shim.chmod(0o755)
    monkeypatch.setenv("PATH", str(shim_directory))

    try:
        macos_value = machine_module._macos_ioplatform_uuid()
    except MachineAttestationError:
        macos_value = None
    try:
        windows_value = machine_module._windows_machine_guid()
    except MachineAttestationError:
        windows_value = None

    assert macos_value != RAW_MACOS_ID
    assert windows_value != RAW_MACOS_ID
    assert not any(marker.exists() for marker in markers)


def test_os_probe_uses_closed_environment_and_bounds_all_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Loader, Git, locale, and PATH inputs cannot influence a system probe."""
    hostile = {
        "PATH": "/attacker/bin",
        "LD_PRELOAD": "/attacker/lib.so",
        "DYLD_INSERT_LIBRARIES": "/attacker/lib.dylib",
        "GIT_DIR": "/attacker/git",
        "GIT_WORK_TREE": "/attacker/worktree",
        "BASH_ENV": "/attacker/bash-env",
        "ENV": "/attacker/shell-env",
    }
    for name, value in hostile.items():
        monkeypatch.setenv(name, value)
    observed: list[dict[str, str]] = []

    def capture(
        argv: list[str],
        *,
        env: dict[str, str],
    ) -> subprocess.CompletedProcess[bytes]:
        observed.append(env)
        return subprocess.CompletedProcess(
            args=argv,
            returncode=0,
            stdout=b"bounded output",
            stderr=b"",
        )

    monkeypatch.setattr(machine_module, "_run_probe_process", capture)
    assert (
        machine_module._run_probe(
            ["/usr/sbin/ioreg", "-rd1"],
            label="test host identity",
        )
        == b"bounded output"
    )
    assert observed == [machine_module._probe_environment()]
    assert observed[0]["PATH"] != hostile["PATH"]
    assert (hostile.keys() - {"PATH"}).isdisjoint(observed[0])

    def excessive(
        argv: list[str],
        *,
        env: dict[str, str],
    ) -> subprocess.CompletedProcess[bytes]:
        del env
        return subprocess.CompletedProcess(
            args=argv,
            returncode=0,
            stdout=b"value",
            stderr=b"x" * (machine_module._MAX_PROBE_OUTPUT_BYTES + 1),
        )

    monkeypatch.setattr(machine_module, "_run_probe_process", excessive)
    with pytest.raises(MachineAttestationError, match="probe failed"):
        machine_module._run_probe(
            ["/usr/sbin/ioreg", "-rd1"],
            label="test host identity",
        )


def test_identity_model_cannot_broaden_claim_or_mismatch_source() -> None:
    """Closed model validation fixes the claim boundary and platform/source pairing."""
    common: dict[str, object] = {
        "platform": MachinePlatform.MACOS,
        "architecture": MachineArchitecture.ARM64,
        "identity_source": MachineIdentitySource.MACOS_IOPLATFORM_UUID,
        "host_identity_commitment_sha256": "a" * 64,
    }
    with pytest.raises(ValueError, match="claim boundary"):
        MachineEnvironmentIdentity.model_validate({**common, "claim_boundary": "hardware proven"})
    with pytest.raises(ValueError, match="source does not match"):
        MachineEnvironmentIdentity.model_validate(
            {**common, "identity_source": MachineIdentitySource.LINUX_MACHINE_ID}
        )


@pytest.mark.parametrize(
    ("system_name", "machine_name", "expected_platform", "expected_architecture"),
    [
        ("Darwin", "arm64", MachinePlatform.MACOS, MachineArchitecture.ARM64),
        ("Linux", "aarch64", MachinePlatform.LINUX, MachineArchitecture.ARM64),
        ("Windows", "AMD64", MachinePlatform.WINDOWS, MachineArchitecture.X86_64),
    ],
)
def test_platform_and_architecture_mapping_is_closed(
    monkeypatch: pytest.MonkeyPatch,
    system_name: str,
    machine_name: str,
    expected_platform: MachinePlatform,
    expected_architecture: MachineArchitecture,
) -> None:
    """Only the Protocol 2 platform and architecture vocabulary is emitted."""
    monkeypatch.setattr(machine_module.host_platform, "system", lambda: system_name)
    monkeypatch.setattr(machine_module.host_platform, "machine", lambda: machine_name)
    assert machine_module._observed_platform() is expected_platform
    assert machine_module._observed_architecture() is expected_architecture

    monkeypatch.setattr(machine_module.host_platform, "system", lambda: "Plan9")
    with pytest.raises(MachineAttestationError, match="no trusted"):
        machine_module._observed_platform()
    monkeypatch.setattr(machine_module.host_platform, "machine", lambda: "mips")
    with pytest.raises(MachineAttestationError, match="not supported"):
        machine_module._observed_architecture()


def _patch_observation(monkeypatch: pytest.MonkeyPatch, raw_identifier: str) -> None:
    """Patch only the internal host probe; public builders remain unchanged."""
    observation = machine_module._ObservedHostIdentity(
        platform=MachinePlatform.MACOS,
        architecture=MachineArchitecture.ARM64,
        identity_source=MachineIdentitySource.MACOS_IOPLATFORM_UUID,
        canonical_identifier=raw_identifier,
    )
    monkeypatch.setattr(machine_module, "_observe_host_identity", lambda: observation)


def _run(argv: list[str]) -> None:
    """Run one local fixture command and fail with bounded diagnostics."""
    completed = subprocess.run(
        argv,
        capture_output=True,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        pytest.fail(completed.stderr or completed.stdout)


def _git_head(repository: Path) -> str:
    """Read the committed fixture identity."""
    return subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        capture_output=True,
        check=True,
        text=True,
    ).stdout.strip()


def _file_sha256(path: Path) -> str:
    """Hash exact fixture bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()
