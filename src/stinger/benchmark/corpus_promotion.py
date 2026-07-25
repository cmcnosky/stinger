"""Mechanically promote an exact validated candidate corpus to the sealed split.

The only permitted scenario-tree mutation is the explicit manifest lifecycle scalar
``benchmark_split: candidate`` becoming ``benchmark_split: sealed``. The builder snapshots
and revalidates both sides, extends the cooperative custody chain, and emits a path-free
statement that can be signed outside the private package.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from collections import Counter
from pathlib import Path

from stinger import RUBRIC_VERSION
from stinger.benchmark.candidate_receipt import (
    CandidateReceiptError,
    CandidateValidationMetadata,
    _candidate_identity_inventory,
    _candidate_validation_inventory,
    _clean_git_head,
    _inventory_tree,
    _load_metadata,
    _read_regular_file,
    _require_loaded_stinger_from_repository,
    _require_real_directory,
    _sha256_json,
    _snapshot_tree,
    _validate_candidate_root_shape,
    _validate_candidate_shape,
    _validate_explicit_manifest_fields,
    _validate_snapshot,
    _verify_access_ledger,
    _verify_canaries,
)
from stinger.benchmark.gates import (
    CANDIDATE_PROMOTION_CONTRACT,
    CANDIDATE_PROMOTION_FORMAT_VERSION,
    CandidatePromotionStatement,
    CorpusScenarioRecord,
    RepositorySize,
    authorize_candidate_validation_receipt,
    candidate_scenario_identity_inventory_sha256,
    candidate_validation_inventory_sha256,
    compiled_benchmark_protocol,
    sealed_scenario_artifact_inventory_sha256,
)
from stinger.benchmark.protocol import BenchmarkSplit
from stinger.benchmark.signing import ProtocolSignatureError
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
from stinger.models import Family, Outcome
from stinger.scenario.loader import Scenario, corpus_hash, discover_scenarios, scenario_hash
from stinger.scenario.manifest import ValidityError, validate_scenario

PROMOTION_STATEMENT_FILE = "candidate-promotion-statement.json"
SEALED_CORPUS_DIRECTORY = "corpus"
SEALED_ACCESS_LEDGER_FILE = "sealed-access-ledger.jsonl"
SEALED_VALIDATION_CONTRACT = "stinger-scenario-validity-v1-docker-sealed"
_SPLIT_LINE = re.compile(
    rb"^(benchmark_split:[ \t]*)candidate([ \t]*(?:#[^\r\n]*)?)(\r?\n?)$",
    flags=re.MULTILINE,
)

__all__ = [
    "PROMOTION_STATEMENT_FILE",
    "SEALED_ACCESS_LEDGER_FILE",
    "SEALED_CORPUS_DIRECTORY",
    "CandidatePromotionError",
    "promote_candidate_corpus",
]


class CandidatePromotionError(Exception):
    """Raised when exact candidate evidence cannot support a sealed promotion."""


def promote_candidate_corpus(
    *,
    candidate_root: Path,
    metadata_file: Path,
    canary_registry: Path,
    access_ledger: Path,
    candidate_receipt: Path,
    candidate_receipt_signature: Path,
    candidate_allowed_signers: Path,
    candidate_signer_identity: str,
    repository: Path,
    verification_image: str,
    promotion_signer_identity: str,
    output_directory: Path,
) -> CandidatePromotionStatement:
    """Create an atomic private sealed package and its public signable statement.

    The output directory contains the sealed scenario tree, an extended private custody
    ledger, and a path-free statement. It is created only after both candidate and sealed
    snapshots pass contained validation and every candidate receipt binding is reproduced.
    """
    if (
        not promotion_signer_identity
        or promotion_signer_identity != promotion_signer_identity.strip()
        or any(character.isspace() for character in promotion_signer_identity)
    ):
        raise CandidatePromotionError("promotion signer identity is invalid")
    try:
        authorization = authorize_candidate_validation_receipt(
            candidate_receipt,
            candidate_receipt_signature,
            candidate_allowed_signers,
            candidate_signer_identity,
        )
    except (OSError, ValueError, ProtocolSignatureError) as exc:
        raise CandidatePromotionError("candidate receipt authorization failed") from exc
    receipt = authorization.receipt
    protocol = compiled_benchmark_protocol()
    try:
        source = _require_real_directory(candidate_root)
        metadata_bytes = _read_regular_file(metadata_file)
        registry_bytes = _read_regular_file(canary_registry)
        ledger_bytes = _read_regular_file(access_ledger)
        metadata = _load_metadata(metadata_bytes)
        initial_commit = _clean_git_head(repository)
        _require_loaded_stinger_from_repository(repository, expected_commit=initial_commit)
        approved_verifier = verify_approved_verification_image(
            repository=repository,
            image=verification_image,
            policy=protocol.verification_image_policy,
        )
        docker_runtime = approved_verifier.docker_runtime
        image_id = approved_verifier.image.image_id
        verification_image_policy_sha256 = approved_verifier.policy_sha256
    except (
        CandidateReceiptError,
        DockerRuntimeError,
        OSError,
        ValueError,
        VerificationImagePolicyError,
    ) as exc:
        raise CandidatePromotionError("candidate promotion input is invalid") from exc
    if (
        initial_commit != receipt.stinger_commit
        or image_id != receipt.verification_image_id
        or verification_image_policy_sha256 != receipt.verification_image_policy_sha256
    ):
        raise CandidatePromotionError("promotion implementation or image differs from validation")
    if hashlib.sha256(metadata_bytes).hexdigest() != receipt.private_metadata_sha256:
        raise CandidatePromotionError("private candidate metadata differs from signed validation")
    _require_output_separate(output_directory, source)
    if output_directory.exists():
        raise CandidatePromotionError("promotion output already exists")
    output_directory.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{output_directory.name}.",
            dir=output_directory.parent,
        )
    )
    try:
        sealed_root = temporary / SEALED_CORPUS_DIRECTORY
        candidate_snapshot = _snapshot_tree(source, sealed_root)
        candidate_scenarios = discover_scenarios(sealed_root)
        _validate_candidate_root_shape(sealed_root)
        _validate_explicit_manifest_fields(candidate_scenarios)
        _validate_candidate_shape(candidate_scenarios, metadata, receipt.scenario_count)
        candidate_hash = corpus_hash(candidate_scenarios)
        if (
            candidate_snapshot.inventory_sha256 != receipt.source_snapshot_sha256
            or candidate_hash != receipt.candidate_corpus_hash
        ):
            raise CandidatePromotionError("candidate snapshot differs from signed validation")
        sizes = {item.scenario_id: item.repository_size for item in metadata.scenarios}
        if _candidate_identity_inventory(candidate_scenarios, sizes) != (
            receipt.scenario_identity_inventory_sha256
        ):
            raise CandidatePromotionError("candidate identity inventory differs from receipt")
        canary_inventory, _ = _verify_canaries(
            candidate_scenarios,
            registry_bytes,
            registry_sha256=hashlib.sha256(registry_bytes).hexdigest(),
        )
        if canary_inventory != receipt.canary_inventory_sha256:
            raise CandidatePromotionError("candidate canary inventory differs from receipt")
        access_root, _, custody_mode = _verify_access_ledger(
            ledger_bytes,
            candidate_corpus_hash=candidate_hash,
            canary_registry_sha256=hashlib.sha256(registry_bytes).hexdigest(),
        )
        if access_root != receipt.access_log_root_sha256:
            raise CandidatePromotionError("candidate custody root differs from receipt")
        rerun_candidate_receipts = _validate_snapshot(
            candidate_scenarios,
            candidate_corpus_hash=candidate_hash,
            stinger_commit=initial_commit,
            verification_image_id=image_id,
            repository=repository,
            verification_image_policy_sha256=verification_image_policy_sha256,
            docker_runtime=docker_runtime,
        )
        if (
            _candidate_validation_inventory(
                candidate_scenarios,
                rerun_candidate_receipts,
            )
            != receipt.validation_inventory_sha256
        ):
            raise CandidatePromotionError("candidate validation receipts are not reproducible")

        candidate_artifacts = {
            scenario.id: scenario_hash(scenario) for scenario in candidate_scenarios
        }
        _promote_manifest_splits(candidate_scenarios)
        sealed_scenarios = discover_scenarios(sealed_root)
        _validate_sealed_shape(sealed_scenarios, metadata, receipt.scenario_count)
        sealed_hash = corpus_hash(sealed_scenarios)
        sealed_snapshot = _inventory_tree(sealed_root)
        sealed_receipts = _validate_sealed_snapshot(
            sealed_scenarios,
            sealed_corpus_hash=sealed_hash,
            stinger_commit=initial_commit,
            verification_image_id=image_id,
            repository=repository,
            verification_image_policy_sha256=verification_image_policy_sha256,
            docker_runtime=docker_runtime,
        )
        sealed_records = _sealed_record_stubs(sealed_scenarios, sizes, sealed_receipts)
        identity_inventory = candidate_scenario_identity_inventory_sha256(sealed_records)
        if identity_inventory != receipt.scenario_identity_inventory_sha256:
            raise CandidatePromotionError("promotion changed scenario identity metadata")
        sealed_artifact_inventory = sealed_scenario_artifact_inventory_sha256(sealed_records)
        sealed_validation_inventory = candidate_validation_inventory_sha256(sealed_records)
        transformation_inventory = _sha256_json(
            {
                "transformations": [
                    {
                        "scenario_id": scenario.id,
                        "candidate_scenario_artifact_sha256": candidate_artifacts[scenario.id],
                        "sealed_scenario_artifact_sha256": scenario_hash(scenario),
                        "sealed_validation_receipt_sha256": sealed_receipts[scenario.id],
                    }
                    for scenario in sorted(sealed_scenarios, key=lambda item: item.id)
                ]
            }
        )
        extended_ledger, sealed_access_root = _extend_access_ledger(
            ledger_bytes,
            previous_root=access_root,
            custody_mode=custody_mode,
            sealed_corpus_hash=sealed_hash,
            canary_registry_sha256=hashlib.sha256(registry_bytes).hexdigest(),
            candidate_receipt_sha256=authorization.receipt_sha256,
            candidate_source_snapshot_sha256=candidate_snapshot.inventory_sha256,
            sealed_source_snapshot_sha256=sealed_snapshot.inventory_sha256,
            transformation_inventory_sha256=transformation_inventory,
        )
        _write_private_file(
            temporary / SEALED_ACCESS_LEDGER_FILE,
            extended_ledger,
            mode=0o600,
        )
        statement = CandidatePromotionStatement(
            format_version=CANDIDATE_PROMOTION_FORMAT_VERSION,
            benchmark_protocol_version=receipt.benchmark_protocol_version,
            rubric_version=RUBRIC_VERSION,
            corpus_version=receipt.corpus_version,
            signer_identity=promotion_signer_identity,
            stinger_commit=initial_commit,
            verification_image_id=image_id,
            verification_image_policy_sha256=verification_image_policy_sha256,
            docker_client_sha256=docker_runtime.client_sha256,
            docker_runtime_fingerprint_sha256=docker_runtime.fingerprint_sha256,
            transformation_contract=CANDIDATE_PROMOTION_CONTRACT,
            candidate_receipt_sha256=authorization.receipt_sha256,
            candidate_corpus_hash=candidate_hash,
            candidate_source_snapshot_sha256=candidate_snapshot.inventory_sha256,
            candidate_validation_inventory_sha256=receipt.validation_inventory_sha256,
            candidate_access_log_root_sha256=access_root,
            sealed_corpus_hash=sealed_hash,
            sealed_source_snapshot_sha256=sealed_snapshot.inventory_sha256,
            sealed_scenario_identity_inventory_sha256=identity_inventory,
            sealed_scenario_artifact_inventory_sha256=sealed_artifact_inventory,
            sealed_validation_inventory_sha256=sealed_validation_inventory,
            transformation_inventory_sha256=transformation_inventory,
            canary_inventory_sha256=canary_inventory,
            sealed_access_log_root_sha256=sealed_access_root,
            scenario_count=len(sealed_scenarios),
        )
        _write_private_file(
            temporary / PROMOTION_STATEMENT_FILE,
            _canonical_json_bytes(statement.model_dump(mode="json")) + b"\n",
            mode=0o644,
        )
        if _clean_git_head(repository) != initial_commit:
            raise CandidatePromotionError("repository changed during candidate promotion")
        try:
            final_verifier = verify_approved_verification_image(
                repository=repository,
                image=verification_image,
                policy=protocol.verification_image_policy,
                docker_runtime=docker_runtime,
            )
        except VerificationImagePolicyError as exc:
            raise CandidatePromotionError(
                "verification image policy or Docker runtime changed during candidate promotion"
            ) from exc
        if (
            final_verifier.image.image_id != image_id
            or final_verifier.policy_sha256 != verification_image_policy_sha256
        ):
            raise CandidatePromotionError("verification image changed during candidate promotion")
        if _inventory_tree(source).inventory_sha256 != candidate_snapshot.inventory_sha256:
            raise CandidatePromotionError("candidate source changed during promotion")
        os.rename(temporary, output_directory)
        return statement
    except (CandidateReceiptError, SandboxError, ValidityError) as exc:
        raise CandidatePromotionError("candidate promotion verification failed") from exc
    except OSError as exc:
        raise CandidatePromotionError("candidate promotion package could not be created") from exc
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def _promote_manifest_splits(scenarios: list[Scenario]) -> None:
    """Apply exactly one byte-local candidate-to-sealed scalar change per manifest."""
    for scenario in scenarios:
        manifest = scenario.directory / "manifest.yaml"
        content = _read_regular_file(manifest)
        transformed, count = _SPLIT_LINE.subn(rb"\1sealed\2\3", content)
        if count != 1 or transformed == content:
            raise CandidatePromotionError("candidate manifest has no unique promotable split")
        before = _manifest_without_split(content)
        after = _manifest_without_split(transformed)
        if before != after:
            raise CandidatePromotionError("promotion attempted to change non-lifecycle metadata")
        descriptor = os.open(manifest, os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0))
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(transformed)
        finally:
            if descriptor >= 0:
                os.close(descriptor)


def _manifest_without_split(content: bytes) -> dict[str, object]:
    """Parse a manifest and remove only its lifecycle split for equality comparison."""
    import yaml

    try:
        raw = yaml.safe_load(content.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise CandidatePromotionError("candidate manifest is invalid") from exc
    if not isinstance(raw, dict):
        raise CandidatePromotionError("candidate manifest is invalid")
    normalized = dict(raw)
    normalized.pop("benchmark_split", None)
    return normalized


def _validate_sealed_shape(
    scenarios: list[Scenario],
    metadata: CandidateValidationMetadata,
    expected_count: int,
) -> None:
    """Require exact identities, unique clusters, balance, and sealed lifecycle."""
    if len(scenarios) != expected_count or len(metadata.scenarios) != expected_count:
        raise CandidatePromotionError("sealed corpus has an invalid scenario count")
    sizes = {item.scenario_id: item.repository_size for item in metadata.scenarios}
    if set(sizes) != {scenario.id for scenario in scenarios}:
        raise CandidatePromotionError("sealed corpus identity set differs from candidate metadata")
    if any(
        scenario.manifest.benchmark_split is not BenchmarkSplit.SEALED
        or scenario.manifest.cluster_id is None
        for scenario in scenarios
    ):
        raise CandidatePromotionError("sealed lifecycle metadata is invalid")
    records = _sealed_record_stubs(
        scenarios,
        sizes,
        {scenario.id: "0" * 64 for scenario in scenarios},
    )

    protocol = compiled_benchmark_protocol()
    family_sizes = Counter((record.family, record.repository_size) for record in records)
    family_counts = Counter(record.family for record in records)
    if len({record.cluster_id for record in records}) != expected_count or any(
        family_counts[family] != protocol.scenarios_per_family
        or any(
            family_sizes[(family, size)] != protocol.repositories_per_size_per_family
            for size in RepositorySize
        )
        for family in Family
    ):
        raise CandidatePromotionError("sealed family, size, or cluster balance is invalid")


def _validate_sealed_snapshot(
    scenarios: list[Scenario],
    *,
    sealed_corpus_hash: str,
    stinger_commit: str,
    verification_image_id: str,
    repository: Path,
    verification_image_policy_sha256: str,
    docker_runtime: DockerRuntimeIdentity,
) -> dict[str, str]:
    """Rerun every sealed scenario validity contract in Docker and derive receipts."""
    sandbox = Sandbox(isolation=Isolation.DOCKER, image=verification_image_id)
    try:
        sandbox.preflight_benchmark(repository)
        verify_docker_runtime(docker_runtime)
    except (DockerRuntimeError, SandboxError) as exc:
        raise CandidatePromotionError("sealed validation preflight failed") from exc
    receipts: dict[str, str] = {}
    for index, scenario in enumerate(scenarios):
        try:
            validate_scenario(scenario.directory, scenario.manifest, sandbox=sandbox)
        except (OSError, SandboxError, ValidityError) as exc:
            raise CandidatePromotionError(
                f"sealed validation failed at ordinal {index + 1}"
            ) from exc
        receipts[scenario.id] = _sha256_json(
            {
                "scenario_id": scenario.id,
                "scenario_artifact_sha256": scenario_hash(scenario),
                "sealed_corpus_hash": sealed_corpus_hash,
                "stinger_commit": stinger_commit,
                "verification_image_id": verification_image_id,
                "verification_image_policy_sha256": verification_image_policy_sha256,
                "validation_contract": SEALED_VALIDATION_CONTRACT,
            }
        )
    return receipts


def _sealed_record_stubs(
    scenarios: list[Scenario],
    sizes: dict[str, RepositorySize],
    validation_receipts: dict[str, str],
) -> tuple[CorpusScenarioRecord, ...]:
    """Create the minimal typed inventory used by public promotion commitments."""
    return tuple(
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
            scenario_artifact_sha256=scenario_hash(scenario),
            machine_validation_receipt_sha256=validation_receipts[scenario.id],
            provenance_receipt_sha256="0" * 64,
            containment_receipt_sha256="0" * 64,
            dummy_safety_receipt_sha256="0" * 64,
        )
        for scenario in scenarios
    )


def _extend_access_ledger(
    ledger: bytes,
    *,
    previous_root: str,
    custody_mode: str,
    sealed_corpus_hash: str,
    canary_registry_sha256: str,
    candidate_receipt_sha256: str,
    candidate_source_snapshot_sha256: str,
    sealed_source_snapshot_sha256: str,
    transformation_inventory_sha256: str,
) -> tuple[bytes, str]:
    """Append one canonical promotion event and return the new verified root."""
    event: dict[str, object] = {
        "event_type": "candidate_promoted_to_sealed",
        "custody_ledger_mode": custody_mode,
        "previous_event_hash": previous_root,
        "stinger_corpus_sha256": sealed_corpus_hash,
        "canary_registry_sha256": canary_registry_sha256,
        "candidate_validation_receipt_sha256": candidate_receipt_sha256,
        "candidate_source_snapshot_sha256": candidate_source_snapshot_sha256,
        "sealed_source_snapshot_sha256": sealed_source_snapshot_sha256,
        "transformation_inventory_sha256": transformation_inventory_sha256,
    }
    event["event_hash"] = _sha256_json(event)
    extended = ledger.rstrip(b"\r\n") + b"\n" + _canonical_json_bytes(event) + b"\n"
    root, _, _ = _verify_access_ledger(
        extended,
        candidate_corpus_hash=sealed_corpus_hash,
        canary_registry_sha256=canary_registry_sha256,
    )
    return extended, root


def _require_output_separate(output: Path, source: Path) -> None:
    """Reject output locations that could overlap any private input tree."""
    resolved_parent = output.parent.resolve()
    resolved_source = source.resolve()
    if output.resolve() == resolved_source or resolved_source in resolved_parent.parents:
        raise CandidatePromotionError("promotion output must be separate from the candidate root")


def _write_private_file(path: Path, content: bytes, *, mode: int) -> None:
    """Create one exact private package file without following links or overwriting."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _canonical_json_bytes(value: object) -> bytes:
    """Encode JSON deterministically for public receipts and private custody events."""
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
