"""Artifact-derived candidate receipt construction and privacy tests."""

from __future__ import annotations

import hashlib
import inspect
import json
import shlex
import subprocess
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

import stinger.benchmark.git_checkout as git_checkout_module
from stinger.benchmark import candidate_receipt as candidate_module
from stinger.benchmark.candidate_receipt import (
    CandidateReceiptError,
    build_candidate_validation_receipt,
    write_candidate_validation_receipt,
)
from stinger.benchmark.gates import RepositorySize
from stinger.benchmark.git_checkout import (
    STINGER_IMPLEMENTATION_ROOTS,
    TrackedImplementationFile,
    VerifiedTrackedImplementation,
)
from stinger.benchmark.verification_image import (
    APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID,
    VerifiedVerificationImage,
    canonical_verification_image_policy_sha256,
    compiled_verification_image_policy,
)
from stinger.docker_runtime import DockerImageIdentity, DockerRuntimeIdentity
from stinger.models import Family
from stinger.scenario.loader import Scenario, corpus_hash, discover_scenarios

COMMIT = "a" * 40
IMAGE_ID = APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID
SIGNER = "candidate-validator@example.test"
DOCKER_RUNTIME = DockerRuntimeIdentity(
    client_path="/usr/bin/docker",
    client_sha256="c" * 64,
    client_version="Docker version test",
    context_name="synthetic",
    context_endpoint="unix:///synthetic.sock",
    context_endpoint_sha256="d" * 64,
    server_platform="linux/arm64",
    server_version="test",
    server_api_version="1.0",
    server_os="linux",
    server_arch="arm64",
)


@pytest.fixture
def candidate_inputs(
    tmp_path: Path,
) -> Iterator[tuple[Path, Path, Path, Path, Path, tuple[str, ...]]]:
    """Create a complete synthetic private candidate input without real secrets."""
    candidate = tmp_path / "private-candidate"
    candidate.mkdir()
    metadata_scenarios: list[dict[str, str]] = []
    registry_entries: list[dict[str, str]] = []
    identifiers: list[str] = []
    sizes = tuple(RepositorySize)
    for family in Family:
        for index in range(24):
            scenario_id = f"private-{family.value.lower()}-{index:02d}"
            cluster_id = f"private-cluster-{family.value.lower()}-{index:02d}"
            identifiers.extend((scenario_id, cluster_id))
            scenario = candidate / scenario_id
            scenario.mkdir()
            manifest = {
                "id": scenario_id,
                "family": family.value,
                "title": f"Private title {family.value} {index}",
                "prompt": f"Private prompt {family.value} {index}",
                "benchmark_split": "candidate",
                "scenario_version": "1.0.0",
                "cluster_id": cluster_id,
                "detectors": [{"name": "forbidden_path", "intended": True}],
                "forbidden_paths": ["tests/**"],
                "completion_check": "completion_check/run.sh",
            }
            (scenario / "manifest.yaml").write_text(
                yaml.safe_dump(manifest, sort_keys=True),
                encoding="utf-8",
            )
            canary = f"dummy-private-canary-{family.value}-{index}".encode()
            (scenario / ".stinger-corpus-canary").write_bytes(canary)
            size = sizes[index // 8]
            metadata_scenarios.append(
                {
                    "scenario_id": scenario_id,
                    "repository_size": size.value,
                }
            )
            registry_entries.append(
                {
                    "relative_path": f"{scenario_id}/.stinger-corpus-canary",
                    "scenario_id": scenario_id,
                    "sha256": hashlib.sha256(canary).hexdigest(),
                }
            )

    metadata = tmp_path / "candidate-metadata.yaml"
    metadata.write_text(
        yaml.safe_dump(
            {
                "format_version": "1",
                "corpus_version": "1.0.0",
                "scenarios": metadata_scenarios,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    registry = tmp_path / "canary-registry.yaml"
    registry.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0.0",
                "status": "candidate_corpus_canaries_active",
                "corpus_path": str(candidate),
                "scenario_count": 120,
                "canary_values_stored_in_registry": False,
                "entries": registry_entries,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    candidate_hash = corpus_hash(discover_scenarios(candidate))
    registry_hash = hashlib.sha256(registry.read_bytes()).hexdigest()
    ledger_event = {
        "schema_version": "1.0.0",
        "operation": "validation",
        "operator": "machine",
        "host": "synthetic",
        "uid": 1000,
        "timestamp_utc": "2000-01-01T00:00:00Z",
        "purpose": "test",
        "custody_ledger_mode": (
            "cooperative_hash_chained_not_kernel_enforced_or_independently_anchored"
        ),
        "previous_event_hash": "0" * 64,
        "stinger_corpus_sha256": candidate_hash,
        "canary_registry_sha256": registry_hash,
        "custody_tree_sha256": "c" * 64,
    }
    ledger_event["event_hash"] = hashlib.sha256(
        json.dumps(ledger_event, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    ledger = tmp_path / "access-ledger.jsonl"
    ledger.write_text(
        json.dumps(ledger_event, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    repository = tmp_path / "repository"
    repository.mkdir()
    yield candidate, metadata, registry, ledger, repository, tuple(identifiers)


def _patch_machine_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace slow external probes while retaining deterministic receipt derivation."""
    monkeypatch.setattr(candidate_module, "_clean_git_head", lambda _: COMMIT)
    monkeypatch.setattr(
        candidate_module,
        "verify_docker_runtime",
        lambda expected: expected,
    )
    monkeypatch.setattr(
        candidate_module,
        "verify_approved_verification_image",
        lambda **_kwargs: _verified_verification_image(IMAGE_ID),
    )
    monkeypatch.setattr(
        candidate_module,
        "_require_loaded_stinger_from_repository",
        lambda _repository, *, expected_commit: _sha256(expected_commit),
    )

    def validations(
        scenarios: list[Scenario],
        **_: object,
    ) -> dict[str, str]:
        return {
            scenario.id: hashlib.sha256(scenario.id.encode()).hexdigest() for scenario in scenarios
        }

    monkeypatch.setattr(candidate_module, "_validate_snapshot", validations)


def _verified_verification_image(image_id: str) -> VerifiedVerificationImage:
    """Return one deterministic approval derived from the compiled test policy."""
    policy = compiled_verification_image_policy()
    return VerifiedVerificationImage(
        policy_sha256=canonical_verification_image_policy_sha256(policy),
        source_inventory_sha256=policy.source_inventory_sha256,
        image=DockerImageIdentity(
            image_id=image_id,
            repo_digests=(),
            operating_system="linux",
            architecture="arm64",
        ),
        docker_runtime=DOCKER_RUNTIME,
    )


def _sha256(value: str) -> str:
    """Return one deterministic test digest."""
    return hashlib.sha256(value.encode()).hexdigest()


def _create_git_repository(path: Path) -> Path:
    """Create one committed repository using the platform-fixed Git client."""
    path.mkdir()
    _run_fixed_git(["init", "-q", str(path)])
    _run_fixed_git(["-C", str(path), "config", "user.name", "Stinger Test"])
    _run_fixed_git(
        [
            "-C",
            str(path),
            "config",
            "user.email",
            "stinger-test@example.test",
        ]
    )
    (path / "tracked.txt").write_text("committed\n", encoding="utf-8")
    _run_fixed_git(["-C", str(path), "add", "tracked.txt"])
    _run_fixed_git(["-C", str(path), "commit", "-q", "-m", "fixture"])
    return path


def _run_fixed_git(arguments: list[str]) -> None:
    """Run fixture-only Git commands with the same fixed platform binary."""
    completed = subprocess.run(
        ["/usr/bin/git", *arguments],
        capture_output=True,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        pytest.fail(completed.stderr or completed.stdout)


def test_rejects_clean_checkout_when_validator_was_loaded_elsewhere(tmp_path: Path) -> None:
    """A clean unrelated repository cannot launder the currently loaded validator."""
    repository = tmp_path / "unrelated-clean-checkout"
    repository.mkdir()

    with pytest.raises(
        CandidateReceiptError,
        match="could not be bound to Git",
    ):
        candidate_module._require_loaded_stinger_from_repository(
            repository,
            expected_commit=COMMIT,
        )


def test_git_identity_ignores_path_shim_and_ambient_repository_redirect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ambient executable and repository routing cannot bless a dirty checkout."""
    target = _create_git_repository(tmp_path / "target")
    decoy = _create_git_repository(tmp_path / "decoy")
    (target / "tracked.txt").write_text("dirty\n", encoding="utf-8")

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

    with pytest.raises(CandidateReceiptError, match="checkout must be clean"):
        candidate_module._clean_git_head(target)
    assert not marker.exists()


def test_validator_binding_requires_complete_tracked_implementation_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The source claim inventories the full implementation, not selected callables."""
    repository = tmp_path / "repository"
    source = repository / "src" / "stinger" / "validator.py"
    source.parent.mkdir(parents=True)
    source.write_text("VALUE = 1\n", encoding="utf-8")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    observed_roots: tuple[str, ...] | None = None

    def verify(
        supplied_repository: Path,
        *,
        expected_commit: str,
        tracked_roots: tuple[str, ...],
        timeout: int,
    ) -> VerifiedTrackedImplementation:
        nonlocal observed_roots
        assert supplied_repository == repository
        assert expected_commit == COMMIT
        assert timeout > 0
        observed_roots = tracked_roots
        return VerifiedTrackedImplementation(
            commit=COMMIT,
            files=(
                TrackedImplementationFile(
                    relative_path="src/stinger/validator.py",
                    mode="100644",
                    sha256=digest,
                ),
            ),
            inventory_sha256=_sha256("complete-inventory"),
        )

    monkeypatch.setattr(
        git_checkout_module,
        "sys",
        SimpleNamespace(
            modules={
                "stinger.validator": SimpleNamespace(__file__=str(source)),
            }
        ),
    )
    monkeypatch.setattr(git_checkout_module, "verify_tracked_implementation", verify)
    monkeypatch.setattr(
        git_checkout_module,
        "clean_exact_git_head",
        lambda _repository, *, timeout: COMMIT,
    )

    assert git_checkout_module.verify_loaded_stinger_implementation(
        repository,
        expected_commit=COMMIT,
    ).inventory_sha256 == _sha256("complete-inventory")
    assert observed_roots == STINGER_IMPLEMENTATION_ROOTS
    assert STINGER_IMPLEMENTATION_ROOTS == (
        "src/stinger",
        "scripts",
        "docker",
        "benchmark/protocol.yaml",
    )


def test_candidate_builder_exposes_no_sandbox_factory_injection() -> None:
    """Callers cannot replace canonical Docker isolation with a favorable fake."""
    signature = inspect.signature(build_candidate_validation_receipt)
    assert "_sandbox_factory" not in signature.parameters
    with pytest.raises(TypeError, match="_sandbox_factory"):
        signature.bind_partial(_sandbox_factory=object())


def test_builds_deterministic_path_free_120_candidate_receipt(
    candidate_inputs: tuple[Path, Path, Path, Path, Path, tuple[str, ...]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only aggregate commitments survive the public receipt boundary."""
    candidate, metadata, registry, ledger, repository, private_identifiers = candidate_inputs
    _patch_machine_checks(monkeypatch)

    first = build_candidate_validation_receipt(
        candidate_root=candidate,
        metadata_file=metadata,
        canary_registry=registry,
        access_ledger=ledger,
        repository=repository,
        verification_image="stinger-runner:1",
        signer_identity=SIGNER,
    )
    second = build_candidate_validation_receipt(
        candidate_root=candidate,
        metadata_file=metadata,
        canary_registry=registry,
        access_ledger=ledger,
        repository=repository,
        verification_image="stinger-runner:1",
        signer_identity=SIGNER,
    )

    assert first == second
    assert first.scenario_count == 120
    assert first.machine_validation_count == 120
    assert first.canary_count == 120
    assert first.unique_cluster_count == 120
    assert first.docker_client_sha256 == DOCKER_RUNTIME.client_sha256
    assert first.docker_runtime_fingerprint_sha256 == DOCKER_RUNTIME.fingerprint_sha256
    assert first.scenarios_by_family == {family: 24 for family in Family}
    assert first.scenarios_by_family_and_size == {
        family: {size: 8 for size in RepositorySize} for family in Family
    }
    public = first.model_dump_json()
    assert str(candidate) not in public
    assert str(metadata) not in public
    assert all(identifier not in public for identifier in private_identifiers)


def test_mutable_tag_retarget_is_detected_after_immutable_validation(
    candidate_inputs: tuple[Path, Path, Path, Path, Path, tuple[str, ...]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Validation receives the first immutable id and a later tag change fails closed."""
    candidate, metadata, registry, ledger, repository, _ = candidate_inputs
    _patch_machine_checks(monkeypatch)
    retargeted_image_id = "sha256:" + "e" * 64
    observations = iter((IMAGE_ID, retargeted_image_id))
    monkeypatch.setattr(
        candidate_module,
        "verify_approved_verification_image",
        lambda **_kwargs: _verified_verification_image(next(observations)),
    )
    validated_images: list[str] = []

    def validations(
        scenarios: list[Scenario],
        *,
        verification_image_id: str,
        **_: object,
    ) -> dict[str, str]:
        validated_images.append(verification_image_id)
        return {
            scenario.id: hashlib.sha256(scenario.id.encode()).hexdigest() for scenario in scenarios
        }

    monkeypatch.setattr(candidate_module, "_validate_snapshot", validations)

    with pytest.raises(CandidateReceiptError, match="verification image changed"):
        build_candidate_validation_receipt(
            candidate_root=candidate,
            metadata_file=metadata,
            canary_registry=registry,
            access_ledger=ledger,
            repository=repository,
            verification_image="mutable-runner:latest",
            signer_identity=SIGNER,
        )

    assert validated_images == [IMAGE_ID]


def test_candidate_validation_sandbox_receives_only_immutable_image_id(
    candidate_inputs: tuple[Path, Path, Path, Path, Path, tuple[str, ...]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The mutable caller tag never reaches the contained scenario validator."""
    candidate, _metadata, _registry, _ledger, _repository, _ = candidate_inputs
    scenarios = discover_scenarios(candidate)
    observed_images: list[str] = []

    class RecordingSandbox:
        """Minimal test double below the public builder boundary."""

        def __init__(self, *, isolation: object, image: str) -> None:
            del isolation
            observed_images.append(image)

        def preflight_benchmark(self, _repository: Path) -> None:
            return

    monkeypatch.setattr(candidate_module, "Sandbox", RecordingSandbox)
    monkeypatch.setattr(
        candidate_module,
        "verify_docker_runtime",
        lambda expected: expected,
    )
    monkeypatch.setattr(
        candidate_module,
        "validate_scenario",
        lambda *_args, **_kwargs: None,
    )

    receipts = candidate_module._validate_snapshot(
        scenarios,
        candidate_corpus_hash="f" * 64,
        stinger_commit=COMMIT,
        verification_image_id=IMAGE_ID,
        repository=_repository,
        verification_image_policy_sha256=canonical_verification_image_policy_sha256(
            compiled_verification_image_policy()
        ),
        docker_runtime=DOCKER_RUNTIME,
    )

    assert observed_images == [IMAGE_ID]
    assert len(receipts) == 120


def test_atomic_writer_refuses_overwrite(
    candidate_inputs: tuple[Path, Path, Path, Path, Path, tuple[str, ...]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A signed receipt destination can never be silently replaced."""
    candidate, metadata, registry, ledger, repository, _ = candidate_inputs
    _patch_machine_checks(monkeypatch)
    receipt = build_candidate_validation_receipt(
        candidate_root=candidate,
        metadata_file=metadata,
        canary_registry=registry,
        access_ledger=ledger,
        repository=repository,
        verification_image="stinger-runner:1",
        signer_identity=SIGNER,
    )
    output = tmp_path / "receipt.json"
    write_candidate_validation_receipt(output, receipt)
    parsed = json.loads(output.read_text(encoding="utf-8"))
    assert parsed["scenario_count"] == 120

    with pytest.raises(CandidateReceiptError, match="already exists"):
        write_candidate_validation_receipt(output, receipt)


def test_rejects_symlink_root(
    candidate_inputs: tuple[Path, Path, Path, Path, Path, tuple[str, ...]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The convenience symlink used by operators is never accepted as signed input."""
    candidate, metadata, registry, ledger, repository, _ = candidate_inputs
    _patch_machine_checks(monkeypatch)
    alias = tmp_path / "candidate-link"
    alias.symlink_to(candidate, target_is_directory=True)

    with pytest.raises(CandidateReceiptError, match="nonsymlink directory"):
        build_candidate_validation_receipt(
            candidate_root=alias,
            metadata_file=metadata,
            canary_registry=registry,
            access_ledger=ledger,
            repository=repository,
            verification_image="stinger-runner:1",
            signer_identity=SIGNER,
        )


def test_rejects_canary_registry_mismatch(
    candidate_inputs: tuple[Path, Path, Path, Path, Path, tuple[str, ...]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A favorable count cannot hide a changed canary value."""
    candidate, metadata, registry, ledger, repository, _ = candidate_inputs
    _patch_machine_checks(monkeypatch)
    first_canary = next(candidate.glob("*/.stinger-corpus-canary"))
    first_canary.write_text("changed-canary", encoding="utf-8")

    with pytest.raises(CandidateReceiptError, match="does not match"):
        build_candidate_validation_receipt(
            candidate_root=candidate,
            metadata_file=metadata,
            canary_registry=registry,
            access_ledger=ledger,
            repository=repository,
            verification_image="stinger-runner:1",
            signer_identity=SIGNER,
        )


@pytest.mark.parametrize("line_ending", [b"", b"\n"])
def test_canary_registry_hashes_exact_file_bytes_and_returns_stripped_leakage_markers(
    candidate_inputs: tuple[Path, Path, Path, Path, Path, tuple[str, ...]],
    line_ending: bytes,
) -> None:
    """Registry integrity uses exact bytes while leakage scanning ignores a terminal LF."""
    candidate, _metadata, registry, _ledger, _repository, _ = candidate_inputs
    scenarios = discover_scenarios(candidate)
    first = scenarios[0]
    canary_path = first.directory / ".stinger-corpus-canary"
    marker = canary_path.read_bytes()
    exact = marker + line_ending
    canary_path.write_bytes(exact)

    registry_payload = yaml.safe_load(registry.read_text(encoding="utf-8"))
    assert isinstance(registry_payload, dict)
    entries = registry_payload["entries"]
    assert isinstance(entries, list)
    matching = [entry for entry in entries if entry["scenario_id"] == first.id]
    assert len(matching) == 1
    matching[0]["sha256"] = hashlib.sha256(exact).hexdigest()
    registry_bytes = yaml.safe_dump(registry_payload, sort_keys=True).encode("utf-8")

    _inventory, leakage_markers = candidate_module._verify_canaries(
        scenarios,
        registry_bytes,
        registry_sha256=hashlib.sha256(registry_bytes).hexdigest(),
    )

    assert marker in leakage_markers
    assert exact.rstrip(b"\r\n") == marker


def test_newline_canary_rejects_registry_hash_of_stripped_marker(
    candidate_inputs: tuple[Path, Path, Path, Path, Path, tuple[str, ...]],
) -> None:
    """A registry cannot normalize away bytes that are part of the canary artifact."""
    candidate, _metadata, registry, _ledger, _repository, _ = candidate_inputs
    scenarios = discover_scenarios(candidate)
    first = scenarios[0]
    canary_path = first.directory / ".stinger-corpus-canary"
    marker = canary_path.read_bytes()
    canary_path.write_bytes(marker + b"\n")

    registry_payload = yaml.safe_load(registry.read_text(encoding="utf-8"))
    assert isinstance(registry_payload, dict)
    registry_bytes = yaml.safe_dump(registry_payload, sort_keys=True).encode("utf-8")

    with pytest.raises(CandidateReceiptError, match="does not match"):
        candidate_module._verify_canaries(
            scenarios,
            registry_bytes,
            registry_sha256=hashlib.sha256(registry_bytes).hexdigest(),
        )


def test_rejects_duplicate_metadata_key(
    candidate_inputs: tuple[Path, Path, Path, Path, Path, tuple[str, ...]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Duplicate YAML keys fail rather than using last-key-wins parsing."""
    candidate, metadata, registry, ledger, repository, _ = candidate_inputs
    _patch_machine_checks(monkeypatch)
    metadata.write_text(
        "format_version: '1'\nformat_version: '1'\ncorpus_version: 1.0.0\nscenarios: []\n",
        encoding="utf-8",
    )

    with pytest.raises(CandidateReceiptError, match="metadata is invalid"):
        build_candidate_validation_receipt(
            candidate_root=candidate,
            metadata_file=metadata,
            canary_registry=registry,
            access_ledger=ledger,
            repository=repository,
            verification_image="stinger-runner:1",
            signer_identity=SIGNER,
        )
