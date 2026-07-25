"""Artifact-derived clean-environment conformance statements and records."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from stinger.benchmark.gates import (
    ConformanceArchitecture,
    ConformanceEnvironmentRecord,
    ConformanceEnvironmentStatement,
    ConformancePlatform,
    authorize_conformance_statement,
    compiled_benchmark_protocol,
)
from stinger.benchmark.git_checkout import (
    DirtyGitCheckoutError,
    GitCheckoutError,
    clean_exact_git_head,
)
from stinger.benchmark.machine_environment import (
    MachineArchitecture,
    MachineAttestationError,
    MachinePlatform,
    MachineWorkflowEvidencePaths,
    machine_environment_identity_sha256,
    verify_local_machine_environment_identity,
    verify_machine_workflow_attestation,
)
from stinger.benchmark.release_evidence import (
    MasterGateWorkflowReceipt,
    ReleaseEvidenceBuilderError,
    run_tracked_master_gate_workflow,
)
from stinger.benchmark.signing import ProtocolSignatureError

__all__ = [
    "CONFORMANCE_WORKFLOW_INPUT_FILE",
    "CONFORMANCE_WORKFLOW_OUTPUT_FILE",
    "CONFORMANCE_WORKFLOW_RECEIPT_FILE",
    "ConformanceBuilderError",
    "ConformanceWorkflowInput",
    "ConformanceWorkflowReceipt",
    "PreparedConformanceWorkflow",
    "build_conformance_environment_record",
    "build_conformance_environment_statement",
    "prepare_conformance_workflow",
    "write_conformance_workflow_package",
    "write_conformance_environment_record",
    "write_conformance_environment_statement",
]

_PROBE_TIMEOUT_SECONDS = 120
_SHA256_LENGTH = 64
_CONFORMANCE_COMMAND = ("bash", "scripts/check.sh")
CONFORMANCE_WORKFLOW_INPUT_FILE = "conformance-workflow-input.json"
CONFORMANCE_WORKFLOW_RECEIPT_FILE = "conformance-workflow-receipt.json"
CONFORMANCE_WORKFLOW_OUTPUT_FILE = "conformance-workflow-output.bin"
_CONFORMANCE_PACKAGE_FILES = frozenset(
    {
        CONFORMANCE_WORKFLOW_INPUT_FILE,
        CONFORMANCE_WORKFLOW_RECEIPT_FILE,
        CONFORMANCE_WORKFLOW_OUTPUT_FILE,
    }
)


class ConformanceBuilderError(Exception):
    """Raised when machine artifacts cannot support a conformance statement."""


class _ClosedModel(BaseModel):
    """Immutable closed schema for exact conformance workflow artifacts."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ConformanceWorkflowInput(_ClosedModel):
    """Canonical role-specific input to the fixed public conformance workflow."""

    format_version: Literal["1"] = "1"
    benchmark_protocol_version: str
    rubric_version: str
    corpus_hash: str
    stinger_commit: str
    command: tuple[str, ...] = _CONFORMANCE_COMMAND

    @field_validator("benchmark_protocol_version", "rubric_version")
    @classmethod
    def _semantic_version(cls, value: str) -> str:
        """Require complete semantic versions."""
        parts = value.split(".")
        if len(parts) != 3 or any(not part.isdigit() for part in parts):
            raise ValueError("conformance workflow versions must be semantic versions")
        return value

    @field_validator("corpus_hash")
    @classmethod
    def _canonical_corpus_hash(cls, value: str) -> str:
        """Require an exact lowercase corpus SHA-256."""
        if len(value) != _SHA256_LENGTH or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise ValueError("conformance workflow corpus hash is invalid")
        return value

    @field_validator("stinger_commit")
    @classmethod
    def _canonical_commit(cls, value: str) -> str:
        """Require one full lowercase Git object id."""
        if len(value) not in {40, 64} or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise ValueError("conformance workflow commit is invalid")
        return value

    @field_validator("command")
    @classmethod
    def _fixed_command(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Prevent caller-selected commands from becoming conformance evidence."""
        if value != _CONFORMANCE_COMMAND:
            raise ValueError("conformance workflow command is fixed")
        return value


class ConformanceWorkflowReceipt(_ClosedModel):
    """Canonical output receipt produced only by the fixed tracked-source gate."""

    format_version: Literal["1"] = "1"
    workflow_input_sha256: str
    master_gate: MasterGateWorkflowReceipt

    @field_validator("workflow_input_sha256")
    @classmethod
    def _canonical_input_hash(cls, value: str) -> str:
        """Require an exact binding to canonical workflow input bytes."""
        if len(value) != _SHA256_LENGTH or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise ValueError("conformance workflow input hash is invalid")
        return value

    @model_validator(mode="after")
    def _fixed_gate(self) -> ConformanceWorkflowReceipt:
        """Require the nested gate to represent the one fixed conformance command."""
        if self.master_gate.command != _CONFORMANCE_COMMAND:
            raise ValueError("conformance workflow receipt has a substituted command")
        return self


@dataclass(frozen=True, slots=True)
class PreparedConformanceWorkflow:
    """Exact typed artifacts from one local, explicitly non-hermetic workflow run."""

    workflow_input: ConformanceWorkflowInput
    workflow_receipt: ConformanceWorkflowReceipt
    workflow_output: bytes = field(repr=False)


def prepare_conformance_workflow(
    *,
    repository: Path,
    toolchain_python: Path,
    expected_stinger_commit: str,
    corpus_hash: str,
) -> PreparedConformanceWorkflow:
    """Run the fixed public-suite gate and derive typed conformance artifacts."""
    protocol = compiled_benchmark_protocol()
    workflow_input = ConformanceWorkflowInput(
        benchmark_protocol_version=protocol.benchmark_protocol_version,
        rubric_version=protocol.rubric_version,
        corpus_hash=corpus_hash,
        stinger_commit=expected_stinger_commit,
    )
    input_bytes = _canonical_model_bytes(workflow_input)
    try:
        master_gate, output = run_tracked_master_gate_workflow(
            repository,
            toolchain_python=toolchain_python,
            expected_stinger_commit=expected_stinger_commit,
        )
    except ReleaseEvidenceBuilderError as exc:
        raise ConformanceBuilderError("fixed conformance workflow failed") from exc
    if master_gate.stinger_commit != expected_stinger_commit:
        raise ConformanceBuilderError("fixed conformance workflow used a different commit")
    workflow_receipt = ConformanceWorkflowReceipt(
        workflow_input_sha256=_sha256(input_bytes),
        master_gate=master_gate,
    )
    return PreparedConformanceWorkflow(
        workflow_input=workflow_input,
        workflow_receipt=workflow_receipt,
        workflow_output=output,
    )


def write_conformance_workflow_package(
    destination: Path,
    prepared: PreparedConformanceWorkflow,
) -> None:
    """Atomically create the complete three-file private conformance package."""
    input_bytes = _canonical_model_bytes(prepared.workflow_input)
    receipt_bytes = _canonical_model_bytes(prepared.workflow_receipt)
    if (
        prepared.workflow_receipt.workflow_input_sha256 != _sha256(input_bytes)
        or prepared.workflow_receipt.master_gate.output_sha256 != _sha256(prepared.workflow_output)
        or prepared.workflow_receipt.master_gate.output_size_bytes != len(prepared.workflow_output)
        or not prepared.workflow_output
    ):
        raise ConformanceBuilderError("prepared conformance workflow is internally inconsistent")
    if destination.exists():
        raise ConformanceBuilderError("conformance workflow package already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent))
    try:
        os.chmod(temporary, 0o700)
        for name, content in {
            CONFORMANCE_WORKFLOW_INPUT_FILE: input_bytes,
            CONFORMANCE_WORKFLOW_RECEIPT_FILE: receipt_bytes,
            CONFORMANCE_WORKFLOW_OUTPUT_FILE: prepared.workflow_output,
        }.items():
            path = temporary / name
            path.write_bytes(content)
            os.chmod(path, 0o600)
        if frozenset(path.name for path in temporary.iterdir()) != _CONFORMANCE_PACKAGE_FILES:
            raise ConformanceBuilderError("conformance workflow package is incomplete")
        temporary.rename(destination)
    except FileExistsError as exc:
        raise ConformanceBuilderError("conformance workflow package already exists") from exc
    except OSError as exc:
        raise ConformanceBuilderError("conformance workflow package could not be created") from exc
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def build_conformance_environment_statement(
    environment_id: str,
    *,
    corpus_hash: str,
    workflow_input: Path,
    workflow_output_inventory: Path,
    workflow_output: Path,
    machine_workflow_evidence: MachineWorkflowEvidencePaths,
    repository: Path,
    signer_identity: str,
) -> ConformanceEnvironmentStatement:
    """Derive one statement from signed workflow and host-derived environment evidence."""
    _require_identifier(environment_id, "environment id")
    _require_identifier(signer_identity, "signer identity")
    if machine_workflow_evidence.signer_identity != signer_identity:
        raise ConformanceBuilderError(
            "machine workflow and conformance signer identities must match"
        )
    if len(corpus_hash) != 64 or any(
        character not in "0123456789abcdef" for character in corpus_hash
    ):
        raise ConformanceBuilderError("corpus hash is not canonical sha256")
    commit = _clean_git_head(repository)
    input_bytes = _read_regular_file(workflow_input, "conformance workflow input")
    receipt_bytes = _read_regular_file(
        workflow_output_inventory,
        "conformance workflow receipt",
    )
    output_bytes = _read_regular_file(workflow_output, "conformance workflow output")
    machine_identity_bytes = _read_regular_file(
        machine_workflow_evidence.identity_artifact,
        "machine identity artifact",
    )
    typed_input = _parse_canonical_model(
        input_bytes,
        ConformanceWorkflowInput,
        "conformance workflow input",
    )
    typed_receipt = _parse_canonical_model(
        receipt_bytes,
        ConformanceWorkflowReceipt,
        "conformance workflow receipt",
    )
    if not isinstance(typed_input, ConformanceWorkflowInput) or not isinstance(
        typed_receipt,
        ConformanceWorkflowReceipt,
    ):
        raise ConformanceBuilderError("typed conformance workflow artifacts are invalid")
    protocol = compiled_benchmark_protocol()
    if (
        typed_input.benchmark_protocol_version != protocol.benchmark_protocol_version
        or typed_input.rubric_version != protocol.rubric_version
        or typed_input.corpus_hash != corpus_hash
        or typed_input.stinger_commit != commit
        or typed_receipt.workflow_input_sha256 != _sha256(input_bytes)
        or typed_receipt.master_gate.stinger_commit != commit
        or typed_receipt.master_gate.output_sha256 != _sha256(output_bytes)
        or typed_receipt.master_gate.output_size_bytes != len(output_bytes)
    ):
        raise ConformanceBuilderError(
            "typed conformance workflow artifacts are not exactly cross-bound"
        )
    try:
        with tempfile.TemporaryDirectory(prefix="stinger-conformance-workflow-") as temporary:
            snapshot = Path(temporary)
            identity_snapshot = snapshot / "machine-identity.json"
            input_snapshot = snapshot / CONFORMANCE_WORKFLOW_INPUT_FILE
            receipt_snapshot = snapshot / CONFORMANCE_WORKFLOW_RECEIPT_FILE
            identity_snapshot.write_bytes(machine_identity_bytes)
            input_snapshot.write_bytes(input_bytes)
            receipt_snapshot.write_bytes(receipt_bytes)
            local_identity = verify_local_machine_environment_identity(identity_snapshot)
            workflow = verify_machine_workflow_attestation(
                machine_identity_artifact=identity_snapshot,
                workflow_input=input_snapshot,
                workflow_receipt=receipt_snapshot,
                attestation=machine_workflow_evidence.attestation,
                signature=machine_workflow_evidence.signature,
                allowed_signers=machine_workflow_evidence.allowed_signers,
                signer_identity=machine_workflow_evidence.signer_identity,
                expected_stinger_commit=commit,
            )
    except MachineAttestationError as exc:
        raise ConformanceBuilderError(
            "signed machine workflow evidence failed verification"
        ) from exc
    if workflow.statement.machine_identity_sha256 != machine_environment_identity_sha256(
        local_identity
    ) or (
        workflow.statement.workflow_input_sha256 != _sha256(input_bytes)
        or workflow.statement.workflow_receipt_sha256 != _sha256(receipt_bytes)
    ):
        raise ConformanceBuilderError(
            "signed machine workflow evidence does not match retained conformance artifacts"
        )
    return ConformanceEnvironmentStatement(
        environment_id=environment_id,
        platform=_conformance_platform(workflow.statement.platform),
        architecture=_conformance_architecture(workflow.statement.architecture),
        python_version=workflow.statement.python_version,
        stinger_commit=workflow.statement.stinger_commit,
        benchmark_protocol_version=protocol.benchmark_protocol_version,
        rubric_version=protocol.rubric_version,
        corpus_hash=corpus_hash,
        environment_fingerprint_sha256=workflow.statement.machine_identity_sha256,
        workflow_input_sha256=workflow.statement.workflow_input_sha256,
        workflow_output_inventory_sha256=workflow.statement.workflow_receipt_sha256,
        signer_identity=signer_identity,
    )


def build_conformance_environment_record(
    statement: Path,
    signature: Path,
    allowed_signers: Path,
    signer_identity: str,
) -> ConformanceEnvironmentRecord:
    """Derive one submission record from a trusted signed conformance statement."""
    try:
        authorization = authorize_conformance_statement(
            statement,
            signature,
            allowed_signers,
            signer_identity,
        )
    except (OSError, ProtocolSignatureError, ValueError) as exc:
        raise ConformanceBuilderError("conformance statement authorization failed") from exc
    content = authorization.statement
    return ConformanceEnvironmentRecord(
        environment_id=content.environment_id,
        platform=content.platform,
        architecture=content.architecture,
        python_version=content.python_version,
        stinger_commit=content.stinger_commit,
        benchmark_protocol_version=content.benchmark_protocol_version,
        rubric_version=content.rubric_version,
        corpus_hash=content.corpus_hash,
        environment_fingerprint_sha256=content.environment_fingerprint_sha256,
        workflow_input_sha256=content.workflow_input_sha256,
        workflow_receipt_sha256=content.workflow_output_inventory_sha256,
        receipt_signature_sha256=authorization.signature_sha256,
        allowed_signers_sha256=authorization.allowed_signers_sha256,
        signer_identity=authorization.identity,
    )


def write_conformance_environment_statement(
    destination: Path,
    statement: ConformanceEnvironmentStatement,
) -> None:
    """Atomically create canonical statement JSON without overwriting."""
    _atomic_create(destination, _canonical_model_bytes(statement))


def write_conformance_environment_record(
    destination: Path,
    record: ConformanceEnvironmentRecord,
) -> None:
    """Atomically create canonical record JSON without overwriting."""
    _atomic_create(destination, _canonical_model_bytes(record))


def _conformance_platform(platform: MachinePlatform) -> ConformancePlatform:
    """Map a verified machine-attestation platform into the release schema."""
    return {
        MachinePlatform.MACOS: ConformancePlatform.MACOS,
        MachinePlatform.LINUX: ConformancePlatform.LINUX,
        MachinePlatform.WINDOWS: ConformancePlatform.WINDOWS,
    }[platform]


def _conformance_architecture(
    architecture: MachineArchitecture,
) -> ConformanceArchitecture:
    """Map a verified machine-attestation architecture into the release schema."""
    return {
        MachineArchitecture.ARM64: ConformanceArchitecture.ARM64,
        MachineArchitecture.X86_64: ConformanceArchitecture.X86_64,
    }[architecture]


def _clean_git_head(repository: Path) -> str:
    """Return exact HEAD only when the supplied conformance checkout is clean."""
    try:
        return clean_exact_git_head(repository, timeout=_PROBE_TIMEOUT_SECONDS)
    except DirtyGitCheckoutError as exc:
        raise ConformanceBuilderError(
            "conformance checkout must be clean at an exact commit"
        ) from exc
    except GitCheckoutError as exc:
        raise ConformanceBuilderError("conformance Git identity could not be established") from exc


def _require_identifier(value: str, label: str) -> None:
    """Require one canonical nonblank identifier."""
    if not value or value != value.strip() or any(character.isspace() for character in value):
        raise ConformanceBuilderError(f"{label} must be nonblank and whitespace-free")


def _sha256(content: bytes) -> str:
    """Return the canonical SHA-256 for exact workflow bytes."""
    import hashlib

    return hashlib.sha256(content).hexdigest()


def _read_regular_file(path: Path, label: str) -> bytes:
    """Read nonempty regular nonsymlink evidence without exposing its path."""
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or metadata.st_size <= 0:
            raise OSError
        content = path.read_bytes()
    except OSError:
        raise ConformanceBuilderError(f"{label} is unavailable") from None
    if not content:
        raise ConformanceBuilderError(f"{label} is empty")
    return content


def _parse_canonical_model(
    content: bytes,
    model: type[ConformanceWorkflowInput] | type[ConformanceWorkflowReceipt],
    label: str,
) -> ConformanceWorkflowInput | ConformanceWorkflowReceipt:
    """Parse duplicate-free canonical workflow JSON."""
    try:
        payload = json.loads(content.decode("utf-8"), object_pairs_hook=_reject_duplicates)
        parsed = model.model_validate(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ConformanceBuilderError(f"{label} is invalid") from None
    if _canonical_model_bytes(parsed) != content:
        raise ConformanceBuilderError(f"{label} is not canonical")
    return parsed


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject ambiguous duplicate JSON keys."""
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON key")
        output[key] = value
    return output


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


def _atomic_create(destination: Path, content: bytes) -> None:
    """Create one canonical file atomically and refuse existing destinations."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor: int | None = None
    temporary: Path | None = None
    try:
        descriptor, raw_temporary = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        temporary = Path(raw_temporary)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise ConformanceBuilderError("conformance output already exists") from exc
        os.unlink(temporary)
        temporary = None
    except OSError as exc:
        raise ConformanceBuilderError("conformance output could not be created") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)
