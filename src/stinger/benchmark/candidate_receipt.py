"""Fail-closed construction of a public candidate-corpus validation receipt.

The receipt deliberately reveals no scenario identifiers, prompts, titles, cluster labels,
canary values, or private filesystem paths. It proves only what its builder can derive
mechanically from an exact private snapshot: corpus shape, identity commitments, canary
coverage, cooperative access-log continuity, and successful Docker validation of every
candidate scenario.

Repository-size strata are signed declarations supplied in a separate private metadata
file. Stinger binds those declarations and checks their required distribution; it does not
pretend that source-tree size has one objective universal classifier.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unicodedata
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from stinger import RUBRIC_VERSION
from stinger.benchmark.gates import (
    CANDIDATE_RECEIPT_FORMAT_VERSION,
    CANDIDATE_VALIDATION_CONTRACT,
    REPOSITORY_SIZE_SOURCE_VERSION,
    CandidateValidationReceipt,
    RepositorySize,
    candidate_scenario_identity_inventory_sha256,
    candidate_validation_inventory_sha256,
    compiled_benchmark_protocol,
)
from stinger.benchmark.git_checkout import (
    DirtyGitCheckoutError,
    GitCheckoutError,
    clean_exact_git_head,
    verify_loaded_stinger_implementation,
)
from stinger.benchmark.protocol import BenchmarkSplit
from stinger.benchmark.verification_image import (
    VerificationImagePolicyError,
    verify_approved_verification_image,
)
from stinger.docker_runtime import (
    DockerRuntimeError,
    DockerRuntimeIdentity,
    verify_docker_runtime,
)
from stinger.harness.sandbox import Isolation, Sandbox, SandboxError
from stinger.models import Family
from stinger.scenario.loader import (
    Scenario,
    corpus_hash,
    discover_scenarios,
    scenario_hash,
)
from stinger.scenario.manifest import ValidityError, validate_scenario

__all__ = [
    "CandidateReceiptError",
    "CandidateScenarioMetadata",
    "CandidateValidationMetadata",
    "build_candidate_validation_receipt",
    "write_candidate_validation_receipt",
]

_MAX_FILES = 50_000
_MAX_FILE_BYTES = 8 * 1024 * 1024
_MAX_TOTAL_BYTES = 512 * 1024 * 1024
_MAX_PATH_DEPTH = 24
_MAX_NAME_BYTES = 255
_READ_CHUNK = 1024 * 1024
_PROBE_TIMEOUT_SECONDS = 120
_ZERO_EVENT_HASH = "0" * 64
_HASH_CHAIN_MODE = "cooperative_hash_chained_not_kernel_enforced_or_independently_anchored"
_REJECTED_NAMES = frozenset(
    {
        ".DS_Store",
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "node_modules",
    }
)


class CandidateReceiptError(Exception):
    """Raised when private evidence cannot support a truthful public receipt."""


class _ClosedModel(BaseModel):
    """Immutable closed schema for private receipt inputs."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class CandidateScenarioMetadata(_ClosedModel):
    """One private repository-size declaration keyed by scenario id."""

    scenario_id: str
    repository_size: RepositorySize

    @field_validator("scenario_id")
    @classmethod
    def _canonical_id(cls, value: str) -> str:
        """Reject blank or whitespace-bearing private identifiers."""
        if not value or value != value.strip() or any(character.isspace() for character in value):
            raise ValueError("scenario_id must be a nonblank identifier without whitespace")
        return value


class CandidateValidationMetadata(_ClosedModel):
    """Private declarations that cannot be derived from current scenario manifests."""

    format_version: str
    corpus_version: str
    scenarios: tuple[CandidateScenarioMetadata, ...]

    @field_validator("corpus_version")
    @classmethod
    def _semantic_version(cls, value: str) -> str:
        """Reuse the release model's semantic corpus-version contract."""
        from stinger.benchmark.gates import SealedCorpusRecord

        SealedCorpusRecord(corpus_version=value, corpus_hash="0" * 64, scenarios=())
        return value


@dataclass(frozen=True, slots=True)
class _TreeFile:
    """One exact source file copied into the validation snapshot."""

    relative_path: str
    sha256: str
    size: int
    executable: bool


@dataclass(frozen=True, slots=True)
class _Snapshot:
    """Exact copied tree plus its canonical inventory commitment."""

    files: tuple[_TreeFile, ...]
    inventory_sha256: str


def build_candidate_validation_receipt(
    *,
    candidate_root: Path,
    metadata_file: Path,
    canary_registry: Path,
    access_ledger: Path,
    repository: Path,
    verification_image: str,
    signer_identity: str,
) -> CandidateValidationReceipt:
    """Build a path-free receipt only after exact snapshot validation succeeds.

    Args:
        candidate_root: Real candidate-corpus directory. Symlink convenience paths are
            rejected so the signed receipt cannot silently point somewhere else.
        metadata_file: Private size declarations and corpus version.
        canary_registry: Private hash-only canary registry.
        access_ledger: Cooperative hash-chained custody ledger.
        repository: Clean Stinger Git checkout supplying the validator implementation.
        verification_image: Docker tag or immutable id to inspect. Validation executes
            against the inspected immutable image id, never the mutable input tag.
        signer_identity: Identity expected to sign the separately written receipt.

    Returns:
        A deterministic public receipt containing hashes and aggregate counts only.

    Raises:
        CandidateReceiptError: If any source, validation, Git, Docker, canary, custody, or
            leakage check cannot be proved.
    """
    protocol = compiled_benchmark_protocol()
    _require_signer_identity(signer_identity)
    metadata_bytes = _read_regular_file(metadata_file)
    metadata = _load_metadata(metadata_bytes)
    if metadata.format_version != CANDIDATE_RECEIPT_FORMAT_VERSION:
        raise CandidateReceiptError("private metadata format is unsupported")

    initial_commit = _clean_git_head(repository)
    _require_loaded_stinger_from_repository(repository, expected_commit=initial_commit)
    try:
        approved_verifier = verify_approved_verification_image(
            repository=repository,
            image=verification_image,
            policy=protocol.verification_image_policy,
        )
    except VerificationImagePolicyError as exc:
        raise CandidateReceiptError(
            "verification image is not approved by the signed protocol policy"
        ) from exc
    initial_docker_runtime = approved_verifier.docker_runtime
    initial_image_id = approved_verifier.image.image_id
    verification_image_policy_sha256 = approved_verifier.policy_sha256
    registry_bytes = _read_regular_file(canary_registry)
    ledger_bytes = _read_regular_file(access_ledger)

    source = _require_real_directory(candidate_root)
    with tempfile.TemporaryDirectory(prefix="stinger-candidate-receipt-") as temporary:
        snapshot_root = Path(temporary) / "candidate"
        first_snapshot = _snapshot_tree(source, snapshot_root)
        _validate_candidate_root_shape(snapshot_root)
        scenarios = discover_scenarios(snapshot_root)
        _validate_explicit_manifest_fields(scenarios)
        _validate_candidate_shape(scenarios, metadata, protocol.total_scenarios)

        candidate_hash = corpus_hash(scenarios)
        sizes = {item.scenario_id: item.repository_size for item in metadata.scenarios}
        identity_inventory = _candidate_identity_inventory(scenarios, sizes)
        canary_inventory, canary_values = _verify_canaries(
            scenarios,
            registry_bytes,
            registry_sha256=hashlib.sha256(registry_bytes).hexdigest(),
        )
        access_root, access_count, ledger_mode = _verify_access_ledger(
            ledger_bytes,
            candidate_corpus_hash=candidate_hash,
            canary_registry_sha256=hashlib.sha256(registry_bytes).hexdigest(),
        )
        validation_receipts = _validate_snapshot(
            scenarios,
            candidate_corpus_hash=candidate_hash,
            stinger_commit=initial_commit,
            verification_image_id=initial_image_id,
            repository=repository,
            verification_image_policy_sha256=verification_image_policy_sha256,
            docker_runtime=initial_docker_runtime,
        )
        validation_inventory = _candidate_validation_inventory(
            scenarios,
            validation_receipts,
        )

        second_inventory = _inventory_tree(source)
        if second_inventory != first_snapshot:
            raise CandidateReceiptError("candidate source changed during validation")

    if _clean_git_head(repository) != initial_commit:
        raise CandidateReceiptError("validator Git state changed during validation")
    try:
        final_verifier = verify_approved_verification_image(
            repository=repository,
            image=verification_image,
            policy=protocol.verification_image_policy,
            docker_runtime=initial_docker_runtime,
        )
    except VerificationImagePolicyError as exc:
        raise CandidateReceiptError(
            "verification image policy or Docker runtime changed during validation"
        ) from exc
    if (
        final_verifier.image.image_id != initial_image_id
        or final_verifier.policy_sha256 != verification_image_policy_sha256
    ):
        raise CandidateReceiptError("verification image changed during validation")

    family_counts = Counter(scenario.manifest.family for scenario in scenarios)
    family_size_counts = Counter(
        (scenario.manifest.family, sizes[scenario.id]) for scenario in scenarios
    )
    receipt = CandidateValidationReceipt(
        format_version=CANDIDATE_RECEIPT_FORMAT_VERSION,
        benchmark_protocol_version=protocol.benchmark_protocol_version,
        rubric_version=RUBRIC_VERSION,
        corpus_version=metadata.corpus_version,
        signer_identity=signer_identity,
        stinger_commit=initial_commit,
        validation_contract=CANDIDATE_VALIDATION_CONTRACT,
        verification_image_id=initial_image_id,
        verification_image_policy_sha256=verification_image_policy_sha256,
        docker_client_sha256=initial_docker_runtime.client_sha256,
        docker_runtime_fingerprint_sha256=initial_docker_runtime.fingerprint_sha256,
        repository_size_source=REPOSITORY_SIZE_SOURCE_VERSION,
        candidate_corpus_hash=candidate_hash,
        source_snapshot_sha256=first_snapshot.inventory_sha256,
        private_metadata_sha256=hashlib.sha256(metadata_bytes).hexdigest(),
        scenario_identity_inventory_sha256=identity_inventory,
        validation_inventory_sha256=validation_inventory,
        canary_inventory_sha256=canary_inventory,
        access_log_root_sha256=access_root,
        custody_ledger_mode=ledger_mode,
        scenario_count=len(scenarios),
        scenarios_by_family={family: family_counts[family] for family in Family},
        scenarios_by_family_and_size={
            family: {
                repository_size: family_size_counts[(family, repository_size)]
                for repository_size in RepositorySize
            }
            for family in Family
        },
        unique_cluster_count=len(
            {
                scenario.manifest.cluster_id
                for scenario in scenarios
                if scenario.manifest.cluster_id is not None
            }
        ),
        machine_validation_count=len(validation_receipts),
        canary_count=len(canary_values),
        access_log_event_count=access_count,
    )
    _validate_receipt_thresholds(receipt)
    _reject_public_leakage(
        receipt,
        scenarios=scenarios,
        canary_values=canary_values,
        private_paths=(
            candidate_root,
            metadata_file,
            canary_registry,
            access_ledger,
            repository,
        ),
    )
    return receipt


def _require_loaded_stinger_from_repository(
    repository: Path,
    *,
    expected_commit: str,
) -> str:
    """Bind the executing validator modules to tracked bytes in the clean checkout.

    A clean checkout argument is not enough when Python imported Stinger from some other
    install. Every scoring/validation module used by this builder must resolve beneath the
    supplied checkout and its exact bytes must match that checkout's committed ``HEAD``.

    Returns:
        A canonical inventory hash over the verified implementation paths and bytes.

    Raises:
        CandidateReceiptError: If loaded code is external, untracked, substituted, or the
            supplied commit differs from the already observed clean ``HEAD``.
    """
    try:
        verified = verify_loaded_stinger_implementation(
            repository,
            expected_commit=expected_commit,
            timeout=_PROBE_TIMEOUT_SECONDS,
        )
    except GitCheckoutError as exc:
        raise CandidateReceiptError(
            f"loaded validator implementation could not be bound to Git: {exc}"
        ) from None
    return verified.inventory_sha256


def write_candidate_validation_receipt(
    destination: Path,
    receipt: CandidateValidationReceipt,
) -> None:
    """Atomically create canonical receipt JSON at a new path."""
    payload = _canonical_json_bytes(receipt.model_dump(mode="json")) + b"\n"
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True)
    descriptor: int | None = None
    temporary: Path | None = None
    try:
        descriptor, raw_temporary = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=parent,
        )
        temporary = Path(raw_temporary)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise CandidateReceiptError("receipt output already exists") from exc
        os.unlink(temporary)
        temporary = None
    except OSError as exc:
        raise CandidateReceiptError("candidate receipt could not be written atomically") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _load_metadata(content: bytes) -> CandidateValidationMetadata:
    """Parse duplicate-key-rejecting private YAML without echoing its contents."""
    try:
        raw = _load_yaml_no_duplicates(content)
        if not isinstance(raw, dict):
            raise TypeError
        metadata = CandidateValidationMetadata.model_validate(raw)
    except (TypeError, UnicodeDecodeError, ValidationError, yaml.YAMLError) as exc:
        raise CandidateReceiptError("private candidate metadata is invalid") from exc
    identifiers = [item.scenario_id for item in metadata.scenarios]
    if len(identifiers) != len(set(identifiers)):
        raise CandidateReceiptError("private candidate metadata has duplicate scenario ids")
    return metadata


class _UniqueKeyLoader(yaml.SafeLoader):
    """YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    """Construct one YAML mapping and fail on duplicate keys."""
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "duplicate key",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _load_yaml_no_duplicates(content: bytes) -> object:
    """Load UTF-8 YAML with duplicate mappings rejected."""
    return yaml.load(content.decode("utf-8"), Loader=_UniqueKeyLoader)


def _require_real_directory(path: Path) -> Path:
    """Return one absolute direct directory while rejecting symlink aliases."""
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CandidateReceiptError("candidate root is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        raise CandidateReceiptError("candidate root must be a real nonsymlink directory")
    return path.absolute()


def _snapshot_tree(source: Path, destination: Path) -> _Snapshot:
    """Safely copy exact regular bytes into an isolated validation snapshot."""
    destination.mkdir(mode=0o700)
    files: list[_TreeFile] = []
    total_bytes = [0]
    _copy_directory(source, destination, PurePosixPath(), files, total_bytes)
    return _snapshot_from_files(files)


def _inventory_tree(source: Path) -> _Snapshot:
    """Re-read an exact source inventory without copying it."""
    files: list[_TreeFile] = []
    total_bytes = [0]
    _inventory_directory(source, PurePosixPath(), files, total_bytes)
    return _snapshot_from_files(files)


def _copy_directory(
    source: Path,
    destination: Path,
    relative: PurePosixPath,
    files: list[_TreeFile],
    total_bytes: list[int],
) -> None:
    """Copy one checked source directory recursively."""
    entries = _checked_directory_entries(source)
    for entry in entries:
        child_relative = relative / entry.name
        _validate_relative_path(child_relative)
        source_path = Path(entry.path)
        metadata = entry.stat(follow_symlinks=False)
        destination_path = destination / entry.name
        if stat.S_ISDIR(metadata.st_mode):
            destination_path.mkdir(mode=0o700)
            _copy_directory(
                source_path,
                destination_path,
                child_relative,
                files,
                total_bytes,
            )
            continue
        content = _checked_file_bytes(source_path, metadata)
        _record_file(
            child_relative,
            content,
            metadata,
            files=files,
            total_bytes=total_bytes,
        )
        mode = 0o700 if metadata.st_mode & 0o111 else 0o600
        descriptor = os.open(
            destination_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            mode,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(content)
        finally:
            if descriptor >= 0:
                os.close(descriptor)


def _inventory_directory(
    source: Path,
    relative: PurePosixPath,
    files: list[_TreeFile],
    total_bytes: list[int],
) -> None:
    """Read one checked source directory recursively into an inventory."""
    for entry in _checked_directory_entries(source):
        child_relative = relative / entry.name
        _validate_relative_path(child_relative)
        source_path = Path(entry.path)
        metadata = entry.stat(follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            _inventory_directory(source_path, child_relative, files, total_bytes)
            continue
        content = _checked_file_bytes(source_path, metadata)
        _record_file(
            child_relative,
            content,
            metadata,
            files=files,
            total_bytes=total_bytes,
        )


def _checked_directory_entries(path: Path) -> list[os.DirEntry[str]]:
    """Return stable entries after rejecting ambiguous names and node types."""
    try:
        directory_metadata = path.lstat()
        if not stat.S_ISDIR(directory_metadata.st_mode) or path.is_symlink():
            raise CandidateReceiptError("candidate tree contains a non-directory node")
        entries = sorted(os.scandir(path), key=lambda item: item.name)
    except OSError as exc:
        raise CandidateReceiptError("candidate tree could not be inventoried") from exc
    folded: set[str] = set()
    for entry in entries:
        name = entry.name
        normalized = unicodedata.normalize("NFC", name)
        if (
            name != normalized
            or name in _REJECTED_NAMES
            or not name
            or name in {".", ".."}
            or "\\" in name
            or any(ord(character) < 32 or ord(character) == 127 for character in name)
            or len(name.encode("utf-8")) > _MAX_NAME_BYTES
        ):
            raise CandidateReceiptError("candidate tree contains an unsafe name")
        key = normalized.casefold()
        if key in folded:
            raise CandidateReceiptError("candidate tree contains a Unicode or case collision")
        folded.add(key)
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise CandidateReceiptError("candidate tree entry changed during inventory") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise CandidateReceiptError("candidate tree contains a symlink")
        if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
            raise CandidateReceiptError("candidate tree contains a special file")
        if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
            raise CandidateReceiptError("candidate tree contains a hard-linked file")
    return entries


def _checked_file_bytes(path: Path, before: os.stat_result) -> bytes:
    """Read one exact regular nonsymlink file and detect in-read mutation."""
    if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_FILE_BYTES:
        raise CandidateReceiptError("candidate tree contains an invalid or oversized file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CandidateReceiptError("candidate file could not be read safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        ):
            raise CandidateReceiptError("candidate file changed before it was read")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, _READ_CHUNK)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ):
            raise CandidateReceiptError("candidate file changed while it was read")
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def _record_file(
    relative: PurePosixPath,
    content: bytes,
    metadata: os.stat_result,
    *,
    files: list[_TreeFile],
    total_bytes: list[int],
) -> None:
    """Append one bounded canonical file record."""
    total_bytes[0] += len(content)
    if len(files) >= _MAX_FILES or total_bytes[0] > _MAX_TOTAL_BYTES:
        raise CandidateReceiptError("candidate tree exceeds receipt safety bounds")
    files.append(
        _TreeFile(
            relative_path=relative.as_posix(),
            sha256=hashlib.sha256(content).hexdigest(),
            size=len(content),
            executable=bool(metadata.st_mode & 0o111),
        )
    )


def _validate_relative_path(path: PurePosixPath) -> None:
    """Reject deep or traversal-like relative paths."""
    if (
        path.is_absolute()
        or ".." in path.parts
        or len(path.parts) > _MAX_PATH_DEPTH
        or not path.parts
    ):
        raise CandidateReceiptError("candidate tree contains an unsafe relative path")


def _snapshot_from_files(files: list[_TreeFile]) -> _Snapshot:
    """Construct a stable tree inventory from checked file records."""
    ordered = tuple(sorted(files, key=lambda item: item.relative_path))
    inventory = [
        {
            "relative_path": item.relative_path,
            "sha256": item.sha256,
            "size": item.size,
            "executable": item.executable,
        }
        for item in ordered
    ]
    return _Snapshot(files=ordered, inventory_sha256=_sha256_json({"files": inventory}))


def _validate_candidate_root_shape(root: Path) -> None:
    """Require the candidate root to contain scenario directories and nothing else."""
    entries = list(root.iterdir())
    if not entries or any(
        not item.is_dir() or not (item / "manifest.yaml").is_file() for item in entries
    ):
        raise CandidateReceiptError("candidate root contains non-scenario top-level material")


def _validate_explicit_manifest_fields(scenarios: list[Scenario]) -> None:
    """Reject candidate manifests that rely on lifecycle or identity defaults."""
    required = {"benchmark_split", "scenario_version", "cluster_id"}
    for index, scenario in enumerate(scenarios):
        try:
            raw = _load_yaml_no_duplicates(_read_regular_file(scenario.directory / "manifest.yaml"))
        except (UnicodeDecodeError, yaml.YAMLError) as exc:
            raise CandidateReceiptError(
                f"candidate manifest {index + 1} is structurally invalid"
            ) from exc
        if not isinstance(raw, dict) or not required.issubset(raw):
            raise CandidateReceiptError(
                f"candidate manifest {index + 1} omits explicit lifecycle metadata"
            )


def _validate_candidate_shape(
    scenarios: list[Scenario],
    metadata: CandidateValidationMetadata,
    expected_count: int,
) -> None:
    """Check count, family balance, candidate split, clusters, and declared sizes."""
    if len(scenarios) != expected_count or len(metadata.scenarios) != expected_count:
        raise CandidateReceiptError("candidate corpus does not contain the required item count")
    by_id = {scenario.id: scenario for scenario in scenarios}
    metadata_by_id = {item.scenario_id: item for item in metadata.scenarios}
    if len(by_id) != expected_count or set(by_id) != set(metadata_by_id):
        raise CandidateReceiptError("private metadata does not exactly cover the candidate corpus")
    clusters = [scenario.manifest.cluster_id for scenario in scenarios]
    if (
        any(
            scenario.manifest.benchmark_split is not BenchmarkSplit.CANDIDATE
            for scenario in scenarios
        )
        or any(cluster is None for cluster in clusters)
        or len(set(clusters)) != expected_count
    ):
        raise CandidateReceiptError("candidate lifecycle or cluster metadata is invalid")
    family_counts = Counter(scenario.manifest.family for scenario in scenarios)
    family_size_counts = Counter(
        (scenario.manifest.family, metadata_by_id[scenario.id].repository_size)
        for scenario in scenarios
    )
    protocol = compiled_benchmark_protocol()
    if any(
        family_counts[family] != protocol.scenarios_per_family
        or any(
            family_size_counts[(family, repository_size)]
            != protocol.repositories_per_size_per_family
            for repository_size in RepositorySize
        )
        for family in Family
    ):
        raise CandidateReceiptError("candidate family or declared-size distribution is invalid")


def _validate_snapshot(
    scenarios: list[Scenario],
    *,
    candidate_corpus_hash: str,
    stinger_commit: str,
    verification_image_id: str,
    repository: Path,
    verification_image_policy_sha256: str,
    docker_runtime: DockerRuntimeIdentity,
) -> dict[str, str]:
    """Run every scenario validity contract in Docker and derive exact receipts."""
    sandbox = Sandbox(isolation=Isolation.DOCKER, image=verification_image_id)
    try:
        sandbox.preflight_benchmark(repository)
        verify_docker_runtime(docker_runtime)
    except (DockerRuntimeError, SandboxError) as exc:
        raise CandidateReceiptError("verification container preflight failed") from exc
    receipts: dict[str, str] = {}
    for index, scenario in enumerate(scenarios):
        artifact_sha256 = scenario_hash(scenario)
        try:
            validate_scenario(
                scenario.directory,
                scenario.manifest,
                sandbox=sandbox,
            )
        except (OSError, SandboxError, ValidityError) as exc:
            raise CandidateReceiptError(
                f"candidate validation failed at ordinal {index + 1}"
            ) from exc
        receipts[scenario.id] = _sha256_json(
            {
                "scenario_id": scenario.id,
                "scenario_artifact_sha256": artifact_sha256,
                "candidate_corpus_hash": candidate_corpus_hash,
                "stinger_commit": stinger_commit,
                "verification_image_id": verification_image_id,
                "verification_image_policy_sha256": verification_image_policy_sha256,
                "validation_contract": CANDIDATE_VALIDATION_CONTRACT,
            }
        )
    return receipts


def _candidate_identity_inventory(
    scenarios: list[Scenario],
    sizes: dict[str, RepositorySize],
) -> str:
    """Compute the same candidate identity commitment enforced by the release gate."""
    from stinger.benchmark.gates import CorpusScenarioRecord
    from stinger.models import Outcome

    records = tuple(
        CorpusScenarioRecord(
            scenario_id=scenario.id,
            family=scenario.manifest.family,
            repository_size=sizes[scenario.id],
            benchmark_split=BenchmarkSplit.SEALED,
            scenario_version=scenario.manifest.scenario_version,
            cluster_id=scenario.manifest.cluster_id or "",
            expected_honest_outcome=(
                Outcome.REFUSED if scenario.manifest.honest_is_refusal else Outcome.HONEST
            ),
            scenario_artifact_sha256="0" * 64,
            machine_validation_receipt_sha256="0" * 64,
            provenance_receipt_sha256="0" * 64,
            containment_receipt_sha256="0" * 64,
            dummy_safety_receipt_sha256="0" * 64,
        )
        for scenario in scenarios
    )
    return candidate_scenario_identity_inventory_sha256(records)


def _candidate_validation_inventory(
    scenarios: list[Scenario],
    receipts: dict[str, str],
) -> str:
    """Compute the release gate's per-scenario validation-receipt commitment."""
    from stinger.benchmark.gates import CorpusScenarioRecord
    from stinger.models import Outcome

    records = tuple(
        CorpusScenarioRecord(
            scenario_id=scenario.id,
            family=scenario.manifest.family,
            repository_size=RepositorySize.SMALL,
            benchmark_split=BenchmarkSplit.SEALED,
            scenario_version=scenario.manifest.scenario_version,
            cluster_id=scenario.manifest.cluster_id or "",
            expected_honest_outcome=(
                Outcome.REFUSED if scenario.manifest.honest_is_refusal else Outcome.HONEST
            ),
            scenario_artifact_sha256="0" * 64,
            machine_validation_receipt_sha256=receipts[scenario.id],
            provenance_receipt_sha256="0" * 64,
            containment_receipt_sha256="0" * 64,
            dummy_safety_receipt_sha256="0" * 64,
        )
        for scenario in scenarios
    )
    return candidate_validation_inventory_sha256(records)


def _verify_canaries(
    scenarios: list[Scenario],
    registry_bytes: bytes,
    *,
    registry_sha256: str,
) -> tuple[str, tuple[bytes, ...]]:
    """Require a bijective hash-only registry and one unique canary per scenario."""
    del registry_sha256  # retained in the ledger binding performed separately
    try:
        raw = _load_yaml_no_duplicates(registry_bytes)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise CandidateReceiptError("canary registry is invalid") from exc
    if not isinstance(raw, dict):
        raise CandidateReceiptError("canary registry is invalid")
    expected_keys = {
        "schema_version",
        "status",
        "corpus_path",
        "scenario_count",
        "canary_values_stored_in_registry",
        "entries",
    }
    if set(raw) != expected_keys or raw.get("canary_values_stored_in_registry") is not False:
        raise CandidateReceiptError("canary registry contract is invalid")
    entries = raw.get("entries")
    if not isinstance(entries, list) or len(entries) != len(scenarios):
        raise CandidateReceiptError("canary registry count is invalid")
    scenario_ids = {scenario.id for scenario in scenarios}
    seen_ids: set[str] = set()
    values: list[bytes] = []
    inventory: list[dict[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"relative_path", "scenario_id", "sha256"}:
            raise CandidateReceiptError("canary registry entry is invalid")
        scenario_id = entry.get("scenario_id")
        relative_path = entry.get("relative_path")
        expected_sha256 = entry.get("sha256")
        if (
            not isinstance(scenario_id, str)
            or scenario_id not in scenario_ids
            or scenario_id in seen_ids
            or not isinstance(relative_path, str)
            or PurePosixPath(relative_path) != PurePosixPath(scenario_id, ".stinger-corpus-canary")
            or not isinstance(expected_sha256, str)
        ):
            raise CandidateReceiptError("canary registry is not bijective")
        canary_bytes = _read_regular_file(
            next(scenario.directory for scenario in scenarios if scenario.id == scenario_id)
            / ".stinger-corpus-canary"
        )
        leakage_marker = canary_bytes.rstrip(b"\r\n")
        if not leakage_marker or hashlib.sha256(canary_bytes).hexdigest() != expected_sha256:
            raise CandidateReceiptError("candidate canary does not match its registry")
        seen_ids.add(scenario_id)
        values.append(leakage_marker)
        inventory.append(
            {
                "scenario_id": scenario_id,
                "relative_path": relative_path,
                "sha256": expected_sha256,
            }
        )
    if seen_ids != scenario_ids or len(values) != len(set(values)):
        raise CandidateReceiptError("candidate canaries are missing or duplicated")
    return (
        _sha256_json({"canaries": sorted(inventory, key=lambda item: item["scenario_id"])}),
        tuple(values),
    )


def _verify_access_ledger(
    content: bytes,
    *,
    candidate_corpus_hash: str,
    canary_registry_sha256: str,
) -> tuple[str, int, str]:
    """Verify the cooperative ledger's canonical event-hash chain."""
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CandidateReceiptError("cooperative access ledger is invalid") from exc
    lines = text.splitlines()
    if not lines:
        raise CandidateReceiptError("cooperative access ledger is empty")
    previous = _ZERO_EVENT_HASH
    mode: str | None = None
    last: dict[str, Any] | None = None
    for line in lines:
        try:
            event = json.loads(line, object_pairs_hook=_reject_duplicate_json_pairs)
        except (json.JSONDecodeError, ValueError) as exc:
            raise CandidateReceiptError("cooperative access ledger is invalid") from exc
        if not isinstance(event, dict):
            raise CandidateReceiptError("cooperative access ledger event is invalid")
        event_hash = event.get("event_hash")
        previous_hash = event.get("previous_event_hash")
        event_mode = event.get("custody_ledger_mode")
        if (
            not isinstance(event_hash, str)
            or not isinstance(previous_hash, str)
            or previous_hash != previous
            or not isinstance(event_mode, str)
            or event_mode != _HASH_CHAIN_MODE
            or _sha256_json({key: value for key, value in event.items() if key != "event_hash"})
            != event_hash
        ):
            raise CandidateReceiptError("cooperative access ledger chain is invalid")
        previous = event_hash
        mode = event_mode
        last = event
    if (
        last is None
        or mode is None
        or last.get("stinger_corpus_sha256") != candidate_corpus_hash
        or last.get("canary_registry_sha256") != canary_registry_sha256
    ):
        raise CandidateReceiptError("cooperative access ledger does not bind current evidence")
    return previous, len(lines), mode


def _reject_duplicate_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON keys rather than accepting last-key-wins semantics."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _validate_receipt_thresholds(receipt: CandidateValidationReceipt) -> None:
    """Refuse a receipt whose aggregate counts do not meet the compiled protocol."""
    protocol = compiled_benchmark_protocol()
    if (
        receipt.scenario_count != protocol.total_scenarios
        or receipt.machine_validation_count != protocol.total_scenarios
        or receipt.canary_count != protocol.total_scenarios
        or receipt.unique_cluster_count != protocol.total_scenarios
        or any(
            receipt.scenarios_by_family.get(family) != protocol.scenarios_per_family
            or receipt.scenarios_by_family_and_size.get(family)
            != {
                repository_size: protocol.repositories_per_size_per_family
                for repository_size in RepositorySize
            }
            for family in Family
        )
    ):
        raise CandidateReceiptError("candidate validation aggregates do not meet Protocol 2")


def _reject_public_leakage(
    receipt: CandidateValidationReceipt,
    *,
    scenarios: list[Scenario],
    canary_values: tuple[bytes, ...],
    private_paths: tuple[Path, ...],
) -> None:
    """Ensure public JSON contains no private labels, values, or host paths."""
    payload = _canonical_json_bytes(receipt.model_dump(mode="json"))
    markers: list[bytes] = list(canary_values)
    for scenario in scenarios:
        markers.extend(
            value.encode("utf-8")
            for value in (
                scenario.id,
                scenario.manifest.title,
                scenario.manifest.prompt,
                scenario.manifest.cluster_id or "",
            )
            if len(value.encode("utf-8")) >= 4
        )
    for path in private_paths:
        for value in {str(path), str(path.absolute())}:
            if len(value.encode("utf-8")) >= 4:
                markers.append(value.encode("utf-8"))
    if any(marker and marker in payload for marker in markers):
        raise CandidateReceiptError("public candidate receipt failed its private-data scan")


def _read_regular_file(path: Path) -> bytes:
    """Read exact nonempty regular nonsymlink bytes without FIFO blocking."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CandidateReceiptError("private receipt input is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise CandidateReceiptError("private receipt input is not a regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, _READ_CHUNK)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    content = b"".join(chunks)
    if not content:
        raise CandidateReceiptError("private receipt input is empty")
    return content


def _require_signer_identity(identity: str) -> None:
    """Require a canonical identity before it enters signed receipt bytes."""
    if (
        not identity
        or identity != identity.strip()
        or any(character.isspace() for character in identity)
    ):
        raise CandidateReceiptError("signer identity must be nonblank and whitespace-free")


def _clean_git_head(repository: Path) -> str:
    """Return exact HEAD only when the supplied checkout is clean."""
    try:
        return clean_exact_git_head(repository, timeout=_PROBE_TIMEOUT_SECONDS)
    except DirtyGitCheckoutError as exc:
        raise CandidateReceiptError("validator checkout must be clean at an exact commit") from exc
    except GitCheckoutError as exc:
        raise CandidateReceiptError("validator Git identity could not be established") from exc


def _sha256_json(payload: object) -> str:
    """Hash one canonical JSON payload."""
    return hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()


def _canonical_json_bytes(payload: object) -> bytes:
    """Serialize one JSON-compatible payload deterministically."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
