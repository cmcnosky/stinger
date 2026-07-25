"""Host-derived machine-environment identity and signed workflow provenance.

This module replaces caller-invented machine identity files with a canonical artifact
derived from an operating-system identity source.  The raw source value never leaves the
process: Stinger emits an application-scoped SHA-256 commitment plus the observed platform
and architecture.

The resulting claim is deliberately narrow.  It distinguishes stable operating-system
environments when their identity sources differ.  It does not prove physical hardware,
TPM-backed identity, cloud-provider identity, organizational independence, or that a
privileged operator did not clone or falsify the operating-system source.  A separately
signed workflow attestation binds the environment artifact to exact workflow input and
receipt bytes and to a clean Stinger commit; the signature proves signer accountability,
not the truth of the underlying host source.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform as host_platform
import re
import stat
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from stinger.benchmark.git_checkout import (
    DirtyGitCheckoutError,
    GitCheckoutError,
    clean_exact_git_head,
)
from stinger.benchmark.signing import (
    ProtocolSignatureError,
    sign_protocol,
    verify_protocol_signature,
)

MACHINE_ENVIRONMENT_IDENTITY_FORMAT_VERSION = "1"
MACHINE_WORKFLOW_ATTESTATION_FORMAT_VERSION = "1"
MACHINE_WORKFLOW_SIGNATURE_NAMESPACE = "stinger-benchmark-machine-workflow"
MACHINE_ENVIRONMENT_CLAIM_BOUNDARY = (
    "application-scoped stable operating-system environment pseudonym and observed "
    "platform/architecture; not TPM, physical-hardware, cloud-provider, organizational-"
    "independence, or anti-cloning proof"
)

_HOST_COMMITMENT_DOMAIN = b"stinger-benchmark-machine-environment-v1\x00"
_COMMIT_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_PYTHON_VERSION_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_LINUX_MACHINE_ID_PATTERN = re.compile(r"[0-9a-fA-F]{32}")
_MACOS_UUID_PATTERN = re.compile(
    rb'"IOPlatformUUID"\s*=\s*"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-'
    rb'[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"'
)
_WINDOWS_GUID_PATTERN = re.compile(
    rb"(?im)^\s*MachineGuid\s+REG_[A-Z0-9_]+\s+([0-9a-fA-F-]{36})\s*$"
)
_READ_CHUNK = 1024 * 1024
_MAX_PROBE_OUTPUT_BYTES = 1024 * 1024
_PROBE_TIMEOUT_SECONDS = 30
_GIT_TIMEOUT_SECONDS = 120
_MACOS_IOREG_CANDIDATES = (Path("/usr/sbin/ioreg"),)
_WINDOWS_REG_CANDIDATES = (
    Path(r"C:\Windows\System32\reg.exe"),
    Path(r"C:\Windows\Sysnative\reg.exe"),
)

__all__ = [
    "MACHINE_ENVIRONMENT_CLAIM_BOUNDARY",
    "MACHINE_ENVIRONMENT_IDENTITY_FORMAT_VERSION",
    "MACHINE_WORKFLOW_ATTESTATION_FORMAT_VERSION",
    "MACHINE_WORKFLOW_SIGNATURE_NAMESPACE",
    "MachineArchitecture",
    "MachineAttestationError",
    "MachineEnvironmentIdentity",
    "MachineIdentitySource",
    "MachinePlatform",
    "MachineWorkflowEvidencePaths",
    "MachineWorkflowAttestation",
    "VerifiedMachineWorkflowAttestation",
    "build_machine_environment_identity",
    "build_machine_workflow_attestation",
    "canonical_machine_environment_identity_bytes",
    "create_machine_environment_identity_artifact",
    "load_machine_environment_identity",
    "machine_environment_identity_sha256",
    "sign_machine_workflow_attestation",
    "verify_local_machine_environment_identity",
    "verify_machine_workflow_attestation",
    "write_machine_workflow_attestation",
]


class MachineAttestationError(Exception):
    """Raised when host identity or workflow provenance cannot be established safely."""


class MachinePlatform(StrEnum):
    """Closed platform names accepted by Benchmark Protocol 2."""

    MACOS = "macos"
    LINUX = "linux"
    WINDOWS = "windows"


class MachineArchitecture(StrEnum):
    """Closed architecture names accepted by Benchmark Protocol 2."""

    ARM64 = "arm64"
    X86_64 = "x86_64"


class MachineIdentitySource(StrEnum):
    """Operating-system source used only inside the local commitment."""

    MACOS_IOPLATFORM_UUID = "macos_ioplatform_uuid"
    LINUX_MACHINE_ID = "linux_machine_id"
    WINDOWS_MACHINE_GUID = "windows_machine_guid"


class _ClosedModel(BaseModel):
    """Immutable JSON model that rejects unrecognized evidence fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class MachineEnvironmentIdentity(_ClosedModel):
    """Stable application-scoped pseudonym for one observed OS environment."""

    format_version: Literal["1"] = "1"
    claim_boundary: str = MACHINE_ENVIRONMENT_CLAIM_BOUNDARY
    platform: MachinePlatform
    architecture: MachineArchitecture
    identity_source: MachineIdentitySource
    host_identity_commitment_sha256: str

    @field_validator("claim_boundary")
    @classmethod
    def _fixed_claim_boundary(cls, value: str) -> str:
        """Prevent callers from broadening the evidence claim."""
        if value != MACHINE_ENVIRONMENT_CLAIM_BOUNDARY:
            raise ValueError("machine-environment claim boundary is fixed")
        return value

    @field_validator("host_identity_commitment_sha256")
    @classmethod
    def _canonical_sha256(cls, value: str) -> str:
        """Require a canonical lowercase SHA-256 commitment."""
        if _SHA256_PATTERN.fullmatch(value) is None:
            raise ValueError("host identity commitment must be canonical sha256")
        return value

    @model_validator(mode="after")
    def _source_matches_platform(self) -> MachineEnvironmentIdentity:
        """Reject a source that could not have produced the declared platform."""
        expected = {
            MachinePlatform.MACOS: MachineIdentitySource.MACOS_IOPLATFORM_UUID,
            MachinePlatform.LINUX: MachineIdentitySource.LINUX_MACHINE_ID,
            MachinePlatform.WINDOWS: MachineIdentitySource.WINDOWS_MACHINE_GUID,
        }
        if self.identity_source is not expected[self.platform]:
            raise ValueError("machine identity source does not match the declared platform")
        return self


class MachineWorkflowAttestation(_ClosedModel):
    """Signed binding from one environment identity to exact workflow artifacts."""

    format_version: Literal["1"] = "1"
    claim_boundary: str = MACHINE_ENVIRONMENT_CLAIM_BOUNDARY
    machine_identity_sha256: str
    host_identity_commitment_sha256: str
    platform: MachinePlatform
    architecture: MachineArchitecture
    identity_source: MachineIdentitySource
    python_version: str
    stinger_commit: str
    workflow_input_sha256: str
    workflow_receipt_sha256: str
    signer_identity: str

    @field_validator("claim_boundary")
    @classmethod
    def _fixed_claim_boundary(cls, value: str) -> str:
        """Prevent callers from broadening the evidence claim."""
        if value != MACHINE_ENVIRONMENT_CLAIM_BOUNDARY:
            raise ValueError("machine-environment claim boundary is fixed")
        return value

    @field_validator(
        "machine_identity_sha256",
        "host_identity_commitment_sha256",
        "workflow_input_sha256",
        "workflow_receipt_sha256",
    )
    @classmethod
    def _canonical_sha256(cls, value: str) -> str:
        """Require canonical lowercase SHA-256 values."""
        if _SHA256_PATTERN.fullmatch(value) is None:
            raise ValueError("machine workflow hash must be canonical sha256")
        return value

    @field_validator("python_version")
    @classmethod
    def _canonical_python_version(cls, value: str) -> str:
        """Require an exact three-component Python runtime version."""
        if _PYTHON_VERSION_PATTERN.fullmatch(value) is None:
            raise ValueError("python version must have three numeric components")
        return value

    @field_validator("stinger_commit")
    @classmethod
    def _canonical_commit(cls, value: str) -> str:
        """Require one full lowercase Git object id."""
        if _COMMIT_PATTERN.fullmatch(value) is None:
            raise ValueError("stinger commit must be a full lowercase Git object id")
        return value

    @field_validator("signer_identity")
    @classmethod
    def _canonical_signer_identity(cls, value: str) -> str:
        """Require one unambiguous allowed-signers principal."""
        if not value or value != value.strip() or any(character.isspace() for character in value):
            raise ValueError("signer identity must be nonblank and whitespace-free")
        return value

    @model_validator(mode="after")
    def _source_matches_platform(self) -> MachineWorkflowAttestation:
        """Reject a source that could not have produced the declared platform."""
        expected = {
            MachinePlatform.MACOS: MachineIdentitySource.MACOS_IOPLATFORM_UUID,
            MachinePlatform.LINUX: MachineIdentitySource.LINUX_MACHINE_ID,
            MachinePlatform.WINDOWS: MachineIdentitySource.WINDOWS_MACHINE_GUID,
        }
        if self.identity_source is not expected[self.platform]:
            raise ValueError("machine identity source does not match the declared platform")
        return self


@dataclass(frozen=True, slots=True)
class VerifiedMachineWorkflowAttestation:
    """Exact artifact and trust bindings from successful workflow verification."""

    statement: MachineWorkflowAttestation
    attestation_sha256: str
    signature_sha256: str
    allowed_signers_sha256: str
    signer_identity: str
    signing_key_fingerprint: str
    signature_namespace: str


@dataclass(frozen=True, slots=True)
class MachineWorkflowEvidencePaths:
    """Paths and external trust inputs needed to verify one workflow attestation."""

    identity_artifact: Path
    attestation: Path
    signature: Path
    allowed_signers: Path
    signer_identity: str


@dataclass(frozen=True, slots=True)
class _ObservedHostIdentity:
    """Canonical raw identity retained only long enough to compute a commitment."""

    platform: MachinePlatform
    architecture: MachineArchitecture
    identity_source: MachineIdentitySource
    canonical_identifier: str


def build_machine_environment_identity() -> MachineEnvironmentIdentity:
    """Observe the current host and derive a nonreversible application-scoped identity."""
    return _identity_from_observation(_observe_host_identity())


def create_machine_environment_identity_artifact(
    destination: Path,
) -> MachineEnvironmentIdentity:
    """Observe the current host and atomically create its canonical identity artifact."""
    identity = build_machine_environment_identity()
    _atomic_create(destination, canonical_machine_environment_identity_bytes(identity))
    return identity


def load_machine_environment_identity(path: Path) -> MachineEnvironmentIdentity:
    """Load an exact canonical identity artifact from a regular nonsymlink file."""
    raw = _read_regular_bytes(path, label="machine environment identity")
    return _parse_canonical_model(
        raw,
        MachineEnvironmentIdentity,
        label="machine environment identity",
    )


def verify_local_machine_environment_identity(path: Path) -> MachineEnvironmentIdentity:
    """Require an identity artifact to equal a fresh observation of this environment."""
    artifact = load_machine_environment_identity(path)
    observed = build_machine_environment_identity()
    if artifact != observed:
        raise MachineAttestationError(
            "machine environment identity does not match the current host observation"
        )
    return artifact


def canonical_machine_environment_identity_bytes(
    identity: MachineEnvironmentIdentity,
) -> bytes:
    """Serialize an identity deterministically for hashing by existing record builders."""
    return _canonical_model_bytes(identity)


def machine_environment_identity_sha256(identity: MachineEnvironmentIdentity) -> str:
    """Hash exact canonical identity bytes."""
    return _sha256(canonical_machine_environment_identity_bytes(identity))


def build_machine_workflow_attestation(
    *,
    machine_identity_artifact: Path,
    workflow_input: Path,
    workflow_receipt: Path,
    repository: Path,
    expected_stinger_commit: str,
    signer_identity: str,
) -> MachineWorkflowAttestation:
    """Bind a locally observed identity to exact workflow bytes and a clean commit.

    The workflow receipt is content-bound, not interpreted here.  A caller-specific builder
    remains responsible for proving that the receipt means the required workflow passed.
    """
    _require_commit(expected_stinger_commit)
    _require_identifier(signer_identity, label="signer identity")
    if _same_path(workflow_input, workflow_receipt):
        raise MachineAttestationError("workflow input and receipt must be distinct artifacts")

    identity_before = verify_local_machine_environment_identity(machine_identity_artifact)
    commit_before = _clean_git_head(repository)
    if commit_before != expected_stinger_commit:
        raise MachineAttestationError("workflow checkout does not match the expected commit")
    input_hash = _sha256_regular_file(workflow_input, label="workflow input")
    receipt_hash = _sha256_regular_file(workflow_receipt, label="workflow receipt")
    commit_after = _clean_git_head(repository)
    identity_after = verify_local_machine_environment_identity(machine_identity_artifact)
    if commit_after != commit_before:
        raise MachineAttestationError("workflow checkout changed during attestation")
    if identity_after != identity_before:
        raise MachineAttestationError("machine environment changed during attestation")

    return MachineWorkflowAttestation(
        machine_identity_sha256=machine_environment_identity_sha256(identity_before),
        host_identity_commitment_sha256=identity_before.host_identity_commitment_sha256,
        platform=identity_before.platform,
        architecture=identity_before.architecture,
        identity_source=identity_before.identity_source,
        python_version=(
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        ),
        stinger_commit=commit_before,
        workflow_input_sha256=input_hash,
        workflow_receipt_sha256=receipt_hash,
        signer_identity=signer_identity,
    )


def write_machine_workflow_attestation(
    destination: Path,
    attestation: MachineWorkflowAttestation,
) -> None:
    """Atomically create canonical workflow-attestation JSON without overwriting."""
    _atomic_create(destination, _canonical_model_bytes(attestation))


def sign_machine_workflow_attestation(
    attestation: Path,
    private_key: Path,
) -> Path:
    """Sign exact attestation bytes in a dedicated OpenSSH namespace."""
    try:
        return sign_protocol(
            attestation,
            private_key,
            namespace=MACHINE_WORKFLOW_SIGNATURE_NAMESPACE,
        )
    except ProtocolSignatureError as exc:
        raise MachineAttestationError("machine workflow attestation signing failed") from exc


def verify_machine_workflow_attestation(
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
    """Verify exact identity, workflow, commit, and external signer bindings.

    Verification can happen on a different host.  It verifies that a trusted signing key
    vouched for the recorded environment pseudonym and exact workflow artifacts; it cannot
    independently establish the physical origin of that pseudonym.
    """
    _require_commit(expected_stinger_commit)
    _require_identifier(signer_identity, label="signer identity")
    if _same_path(workflow_input, workflow_receipt):
        raise MachineAttestationError("workflow input and receipt must be distinct artifacts")
    raw_attestation = _read_regular_bytes(attestation, label="machine workflow attestation")
    statement = _parse_canonical_model(
        raw_attestation,
        MachineWorkflowAttestation,
        label="machine workflow attestation",
    )
    try:
        verification = verify_protocol_signature(
            attestation,
            signature,
            allowed_signers,
            signer_identity,
            namespace=MACHINE_WORKFLOW_SIGNATURE_NAMESPACE,
        )
    except ProtocolSignatureError as exc:
        raise MachineAttestationError("machine workflow attestation authorization failed") from exc
    if verification.protocol_sha256 != _sha256(raw_attestation):
        raise MachineAttestationError("machine workflow attestation changed during verification")

    identity = load_machine_environment_identity(machine_identity_artifact)
    expected_identity_hash = machine_environment_identity_sha256(identity)
    if (
        statement.machine_identity_sha256 != expected_identity_hash
        or statement.host_identity_commitment_sha256 != identity.host_identity_commitment_sha256
        or statement.platform is not identity.platform
        or statement.architecture is not identity.architecture
        or statement.identity_source is not identity.identity_source
    ):
        raise MachineAttestationError(
            "machine workflow attestation does not bind the supplied identity artifact"
        )
    if statement.workflow_input_sha256 != _sha256_regular_file(
        workflow_input,
        label="workflow input",
    ):
        raise MachineAttestationError(
            "machine workflow attestation does not bind the supplied workflow input"
        )
    if statement.workflow_receipt_sha256 != _sha256_regular_file(
        workflow_receipt,
        label="workflow receipt",
    ):
        raise MachineAttestationError(
            "machine workflow attestation does not bind the supplied workflow receipt"
        )
    if (
        statement.stinger_commit != expected_stinger_commit
        or statement.signer_identity != signer_identity
    ):
        raise MachineAttestationError(
            "machine workflow attestation does not bind the expected commit and signer"
        )
    return VerifiedMachineWorkflowAttestation(
        statement=statement,
        attestation_sha256=verification.protocol_sha256,
        signature_sha256=verification.signature_sha256,
        allowed_signers_sha256=verification.allowed_signers_sha256,
        signer_identity=verification.identity,
        signing_key_fingerprint=verification.signing_key_fingerprint,
        signature_namespace=verification.namespace,
    )


def _identity_from_observation(
    observation: _ObservedHostIdentity,
) -> MachineEnvironmentIdentity:
    """Derive public identity fields without retaining the raw host identifier."""
    payload = (
        _HOST_COMMITMENT_DOMAIN
        + observation.platform.value.encode("ascii")
        + b"\x00"
        + observation.architecture.value.encode("ascii")
        + b"\x00"
        + observation.identity_source.value.encode("ascii")
        + b"\x00"
        + observation.canonical_identifier.encode("ascii")
    )
    return MachineEnvironmentIdentity(
        platform=observation.platform,
        architecture=observation.architecture,
        identity_source=observation.identity_source,
        host_identity_commitment_sha256=_sha256(payload),
    )


def _observe_host_identity() -> _ObservedHostIdentity:
    """Observe one supported host source, rejecting ambiguous container identities."""
    platform = _observed_platform()
    architecture = _observed_architecture()
    if platform is MachinePlatform.LINUX:
        if _linux_container_observed():
            raise MachineAttestationError(
                "container-scoped Linux identity cannot establish a stable host environment"
            )
        source = MachineIdentitySource.LINUX_MACHINE_ID
        identifier = _linux_machine_id()
    elif platform is MachinePlatform.MACOS:
        source = MachineIdentitySource.MACOS_IOPLATFORM_UUID
        identifier = _macos_ioplatform_uuid()
    else:
        source = MachineIdentitySource.WINDOWS_MACHINE_GUID
        identifier = _windows_machine_guid()
    return _ObservedHostIdentity(
        platform=platform,
        architecture=architecture,
        identity_source=source,
        canonical_identifier=identifier,
    )


def _observed_platform() -> MachinePlatform:
    """Map the running kernel to the Protocol 2 platform set."""
    mapping = {
        "darwin": MachinePlatform.MACOS,
        "linux": MachinePlatform.LINUX,
        "windows": MachinePlatform.WINDOWS,
    }
    try:
        return mapping[host_platform.system().casefold()]
    except KeyError as exc:
        raise MachineAttestationError(
            "host platform has no trusted machine identity source"
        ) from exc


def _observed_architecture() -> MachineArchitecture:
    """Map the running execution architecture to the Protocol 2 set."""
    observed = host_platform.machine().casefold()
    if observed in {"arm64", "aarch64"}:
        return MachineArchitecture.ARM64
    if observed in {"x86_64", "amd64"}:
        return MachineArchitecture.X86_64
    raise MachineAttestationError("host architecture is not supported by Protocol 2")


def _macos_ioplatform_uuid() -> str:
    """Read and canonicalize the macOS platform UUID without exposing it."""
    executable = _fixed_probe_executable(
        _MACOS_IOREG_CANDIDATES,
        label="macOS host identity",
    )
    output = _run_probe(
        [str(executable), "-rd1", "-c", "IOPlatformExpertDevice"],
        label="macOS host identity",
    )
    matches = set(_MACOS_UUID_PATTERN.findall(output))
    if len(matches) != 1:
        raise MachineAttestationError("macOS host identity is missing or ambiguous")
    return _canonical_uuid(next(iter(matches)), label="macOS host identity")


def _linux_machine_id(
    paths: tuple[Path, ...] = (
        Path("/etc/machine-id"),
        Path("/var/lib/dbus/machine-id"),
    ),
) -> str:
    """Read a unique canonical Linux machine-id from real system files."""
    identifiers: set[str] = set()
    existing = False
    for path in paths:
        if not path.exists() and not path.is_symlink():
            continue
        existing = True
        raw = _read_regular_bytes(path, label="Linux machine identity", max_bytes=4096)
        try:
            value = raw.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise MachineAttestationError("Linux machine identity is not canonical") from exc
        if _LINUX_MACHINE_ID_PATTERN.fullmatch(value) is None or int(value, 16) == 0:
            raise MachineAttestationError("Linux machine identity is not canonical")
        identifiers.add(value.casefold())
    if not existing or len(identifiers) != 1:
        raise MachineAttestationError("Linux machine identity is missing or ambiguous")
    return next(iter(identifiers))


def _windows_machine_guid() -> str:
    """Read and canonicalize the Windows MachineGuid without exposing it."""
    executable = _fixed_probe_executable(
        _WINDOWS_REG_CANDIDATES,
        label="Windows host identity",
    )
    output = _run_probe(
        [
            str(executable),
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ],
        label="Windows host identity",
    )
    matches = set(_WINDOWS_GUID_PATTERN.findall(output))
    if len(matches) != 1:
        raise MachineAttestationError("Windows host identity is missing or ambiguous")
    return _canonical_uuid(next(iter(matches)), label="Windows host identity")


def _canonical_uuid(raw: bytes, *, label: str) -> str:
    """Canonicalize a non-null UUID without putting the raw value in diagnostics."""
    try:
        parsed = uuid.UUID(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise MachineAttestationError(f"{label} is not canonical") from exc
    if parsed.int in {0, (1 << 128) - 1}:
        raise MachineAttestationError(f"{label} is not canonical")
    return str(parsed)


def _linux_container_observed() -> bool:
    """Conservatively reject Linux identities observed from a container namespace."""
    if any(
        path.exists() or path.is_symlink()
        for path in (Path("/.dockerenv"), Path("/run/.containerenv"))
    ):
        return True
    markers = (b"docker", b"containerd", b"kubepods", b"podman", b"libpod", b"lxc")
    for path in (Path("/proc/1/cgroup"), Path("/proc/self/cgroup")):
        try:
            content = path.read_bytes().lower()
        except OSError:
            continue
        if any(marker in content for marker in markers):
            return True
    return False


def _run_probe(argv: list[str], *, label: str) -> bytes:
    """Run one absolute host probe with a closed environment and bounded output."""
    if not argv or not Path(argv[0]).is_absolute():
        raise MachineAttestationError(f"{label} probe is not a fixed system executable")
    try:
        completed = _run_probe_process(
            argv,
            env=_probe_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MachineAttestationError(f"{label} probe failed") from exc
    if (
        completed.returncode != 0
        or not completed.stdout
        or len(completed.stdout) > _MAX_PROBE_OUTPUT_BYTES
        or len(completed.stderr) > _MAX_PROBE_OUTPUT_BYTES
    ):
        raise MachineAttestationError(f"{label} probe failed")
    return completed.stdout


def _run_probe_process(
    argv: list[str],
    *,
    env: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    """Launch an already-resolved system probe without a shell."""
    return subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=_PROBE_TIMEOUT_SECONDS,
        env=env,
    )


def _probe_environment() -> dict[str, str]:
    """Return the complete, non-caller-controlled environment for OS probes."""
    if os.name == "nt":
        return {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": r"C:\Windows\System32",
            "SYSTEMROOT": r"C:\Windows",
        }
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    }


def _fixed_probe_executable(
    candidates: tuple[Path, ...],
    *,
    label: str,
) -> Path:
    """Resolve a host probe only from a fixed platform allowlist."""
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except OSError:
            continue
        if (
            resolved.is_absolute()
            and stat.S_ISREG(metadata.st_mode)
            and os.access(resolved, os.X_OK)
        ):
            return resolved
    raise MachineAttestationError(f"{label} probe is unavailable")


def _clean_git_head(repository: Path) -> str:
    """Return exact HEAD only when the repository is a real, clean checkout."""
    try:
        return clean_exact_git_head(repository, timeout=_GIT_TIMEOUT_SECONDS)
    except DirtyGitCheckoutError as exc:
        raise MachineAttestationError("workflow checkout must be clean at an exact commit") from exc
    except GitCheckoutError as exc:
        raise MachineAttestationError("workflow Git identity could not be established") from exc


def _parse_canonical_model[ModelT: BaseModel](
    raw: bytes,
    model_type: type[ModelT],
    *,
    label: str,
) -> ModelT:
    """Parse closed JSON while rejecting duplicate keys and noncanonical bytes."""
    try:
        decoded = raw.decode("utf-8")
        parsed = json.loads(decoded, object_pairs_hook=_reject_duplicate_keys)
        model = model_type.model_validate(parsed)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise MachineAttestationError(f"{label} is not valid closed JSON") from exc
    if _canonical_model_bytes(model) != raw:
        raise MachineAttestationError(f"{label} is not canonical JSON")
    return model


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject ambiguous JSON objects before Pydantic validation."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _canonical_model_bytes(model: BaseModel) -> bytes:
    """Serialize one closed model deterministically."""
    return (
        json.dumps(
            model.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _sha256_regular_file(path: Path, *, label: str) -> str:
    """Hash exact nonempty bytes from a regular nonsymlink artifact."""
    digest = hashlib.sha256()
    size = 0
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise MachineAttestationError(f"{label} must be a readable regular file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise MachineAttestationError(f"{label} must be a readable regular file")
        while True:
            chunk = os.read(descriptor, _READ_CHUNK)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    finally:
        os.close(descriptor)
    if size == 0:
        raise MachineAttestationError(f"{label} must not be empty")
    return digest.hexdigest()


def _read_regular_bytes(
    path: Path,
    *,
    label: str,
    max_bytes: int | None = None,
) -> bytes:
    """Read exact bytes from a regular nonsymlink artifact with an optional bound."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise MachineAttestationError(f"{label} must be a readable regular file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise MachineAttestationError(f"{label} must be a readable regular file")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, _READ_CHUNK)
            if not chunk:
                break
            size += len(chunk)
            if max_bytes is not None and size > max_bytes:
                raise MachineAttestationError(f"{label} exceeds the safe size limit")
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    content = b"".join(chunks)
    if not content:
        raise MachineAttestationError(f"{label} must not be empty")
    return content


def _atomic_create(destination: Path, content: bytes) -> None:
    """Create one mode-0600 artifact atomically without following output symlinks."""
    parent = destination.parent
    if parent.is_symlink() or not parent.is_dir():
        raise MachineAttestationError("machine-attestation output parent must be a real directory")
    if destination.exists() or destination.is_symlink():
        raise MachineAttestationError("machine-attestation output already exists")
    descriptor: int | None = None
    temporary: Path | None = None
    try:
        descriptor, raw_temporary = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=parent,
        )
        temporary = Path(raw_temporary)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise MachineAttestationError("machine-attestation output already exists") from exc
        temporary.unlink()
        temporary = None
    except OSError as exc:
        raise MachineAttestationError("machine-attestation output could not be created") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _same_path(left: Path, right: Path) -> bool:
    """Compare input artifact paths without requiring that they already exist."""
    return left.absolute() == right.absolute() or left.resolve(strict=False) == right.resolve(
        strict=False
    )


def _require_commit(value: str) -> None:
    """Require one full lowercase Git object id."""
    if _COMMIT_PATTERN.fullmatch(value) is None:
        raise MachineAttestationError("expected Stinger commit must be a full object id")


def _require_identifier(value: str, *, label: str) -> None:
    """Require one nonblank whitespace-free identifier."""
    if not value or value != value.strip() or any(character.isspace() for character in value):
        raise MachineAttestationError(f"{label} must be nonblank and whitespace-free")


def _sha256(content: bytes) -> str:
    """Return one lowercase SHA-256 digest."""
    return hashlib.sha256(content).hexdigest()
