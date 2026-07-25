"""Exact candidate-to-sealed corpus promotion construction tests."""

from __future__ import annotations

import hashlib
import inspect
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

import stinger.docker_runtime as docker_runtime_module
import stinger.harness.sandbox as sandbox_module
from stinger.benchmark import candidate_receipt as candidate_module
from stinger.benchmark import corpus_promotion as promotion_module
from stinger.benchmark.candidate_receipt import (
    _inventory_tree,
    _sha256_json,
    _verify_access_ledger,
    build_candidate_validation_receipt,
    write_candidate_validation_receipt,
)
from stinger.benchmark.corpus_promotion import (
    PROMOTION_STATEMENT_FILE,
    SEALED_ACCESS_LEDGER_FILE,
    SEALED_CORPUS_DIRECTORY,
    SEALED_VALIDATION_CONTRACT,
    CandidatePromotionError,
    _sealed_record_stubs,
    promote_candidate_corpus,
)
from stinger.benchmark.gates import (
    CandidatePromotionStatement,
    RepositorySize,
    candidate_validation_inventory_sha256,
    sealed_scenario_artifact_inventory_sha256,
)
from stinger.benchmark.signing import sign_candidate_validation_receipt
from stinger.benchmark.verification_image import (
    APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID,
    VerifiedVerificationImage,
    canonical_verification_image_policy_sha256,
    compiled_verification_image_policy,
)
from stinger.docker_runtime import DockerImageIdentity, DockerRuntimeIdentity
from stinger.models import Family
from stinger.scenario.loader import corpus_hash, discover_scenarios, scenario_hash
from stinger.scenario.manifest import ValidityError

COMMIT = "a" * 40
IMAGE_ID = APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID
CANDIDATE_SIGNER = "candidate-validator@example.test"
PROMOTION_SIGNER = "corpus-promoter@example.test"
VERIFICATION_IMAGE = "stinger-runner:1"
_FIXED_TEST_CLIENT = Path("/usr/bin/true")
DOCKER_RUNTIME = DockerRuntimeIdentity(
    client_path=str(_FIXED_TEST_CLIENT),
    client_sha256=hashlib.sha256(_FIXED_TEST_CLIENT.read_bytes()).hexdigest(),
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


@dataclass(frozen=True, slots=True)
class _PromotionInputs:
    """One complete synthetic, signed candidate corpus promotion input set."""

    candidate: Path
    metadata: Path
    registry: Path
    ledger: Path
    repository: Path
    receipt: Path
    signature: Path
    allowed_signers: Path
    private_key: Path


def _accept_validation(*_: object, **__: object) -> None:
    """Stand in for a successful validity contract without executing a container."""


def _reject_validation(*_: object, **__: object) -> None:
    """Stand in for one mechanically failed scenario validity contract."""
    raise ValidityError("synthetic validation failure")


def _patch_machine_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin Git, image, and contained validation probes without weakening derivation."""
    monkeypatch.setattr(candidate_module, "_clean_git_head", lambda _: COMMIT)
    monkeypatch.setattr(
        candidate_module,
        "verify_docker_runtime",
        lambda expected: expected,
    )
    monkeypatch.setattr(
        candidate_module,
        "verify_approved_verification_image",
        lambda **_kwargs: _verified_verification_image(),
    )
    monkeypatch.setattr(
        candidate_module,
        "_require_loaded_stinger_from_repository",
        lambda _repository, *, expected_commit: hashlib.sha256(
            expected_commit.encode()
        ).hexdigest(),
    )
    monkeypatch.setattr(candidate_module, "validate_scenario", _accept_validation)
    monkeypatch.setattr(promotion_module, "_clean_git_head", lambda _: COMMIT)
    monkeypatch.setattr(
        promotion_module,
        "verify_docker_runtime",
        lambda expected: expected,
    )
    monkeypatch.setattr(
        promotion_module,
        "verify_approved_verification_image",
        lambda **_kwargs: _verified_verification_image(),
    )
    monkeypatch.setattr(
        promotion_module,
        "_require_loaded_stinger_from_repository",
        lambda _repository, *, expected_commit: hashlib.sha256(
            expected_commit.encode()
        ).hexdigest(),
    )
    monkeypatch.setattr(promotion_module, "validate_scenario", _accept_validation)
    monkeypatch.setattr(sandbox_module, "observe_docker_runtime", lambda: DOCKER_RUNTIME)
    monkeypatch.setattr(
        sandbox_module,
        "verify_docker_runtime",
        lambda expected: expected,
    )
    monkeypatch.setattr(
        sandbox_module,
        "verify_approved_verification_image",
        lambda **_kwargs: _verified_verification_image(),
    )
    monkeypatch.setattr(
        docker_runtime_module,
        "resolve_docker_client",
        lambda: _FIXED_TEST_CLIENT,
    )
    monkeypatch.setattr(
        sandbox_module,
        "_run_sandbox_process",
        lambda argv, *, cwd, timeout, environment: subprocess.CompletedProcess(
            args=list(argv),
            returncode=0,
            stdout="",
            stderr="",
        ),
    )


def _verified_verification_image() -> VerifiedVerificationImage:
    """Return one deterministic compiled-policy approval for Docker test doubles."""
    policy = compiled_verification_image_policy()
    return VerifiedVerificationImage(
        policy_sha256=canonical_verification_image_policy_sha256(policy),
        source_inventory_sha256=policy.source_inventory_sha256,
        image=DockerImageIdentity(
            image_id=IMAGE_ID,
            repo_digests=(),
            operating_system="linux",
            architecture="arm64",
        ),
        docker_runtime=DOCKER_RUNTIME,
    )


def _new_signing_identity(
    root: Path,
    *,
    label: str,
    identity: str = CANDIDATE_SIGNER,
) -> tuple[Path, Path]:
    """Create one ephemeral Ed25519 identity and exact trust policy."""
    private_key = root / f"{label}.key"
    generated = subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            f"{label}-test-only",
            "-f",
            str(private_key),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    if generated.returncode != 0:
        pytest.fail(f"could not generate test signing key: {generated.stderr}")
    public_key = Path(f"{private_key}.pub").read_text(encoding="utf-8").strip()
    allowed_signers = root / f"{label}.allowed_signers"
    allowed_signers.write_text(f"{identity} {public_key}\n", encoding="utf-8")
    return private_key, allowed_signers


def _tree_files(root: Path) -> dict[str, bytes]:
    """Read one test tree as a relative-path to exact-bytes mapping."""
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _build_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> _PromotionInputs:
    """Create, mechanically validate, write, and sign a balanced 120-item candidate."""
    _patch_machine_environment(monkeypatch)
    candidate = tmp_path / "private-candidate"
    candidate.mkdir()
    metadata_scenarios: list[dict[str, str]] = []
    registry_entries: list[dict[str, str]] = []
    sizes = tuple(RepositorySize)
    for family in Family:
        for index in range(24):
            scenario_id = f"private-{family.value.lower()}-{index:02d}"
            scenario = candidate / scenario_id
            scenario.mkdir()
            manifest = {
                "id": scenario_id,
                "family": family.value,
                "title": f"Private title {family.value} {index}",
                "prompt": f"Private prompt {family.value} {index}",
                "benchmark_split": "candidate",
                "scenario_version": "1.0.0",
                "cluster_id": f"private-cluster-{family.value.lower()}-{index:02d}",
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
            metadata_scenarios.append(
                {
                    "scenario_id": scenario_id,
                    "repository_size": sizes[index // 8].value,
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
    ledger_event["event_hash"] = _sha256_json(ledger_event)
    ledger = tmp_path / "access-ledger.jsonl"
    ledger.write_text(
        json.dumps(ledger_event, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    repository = tmp_path / "repository"
    repository.mkdir()
    receipt_model = build_candidate_validation_receipt(
        candidate_root=candidate,
        metadata_file=metadata,
        canary_registry=registry,
        access_ledger=ledger,
        repository=repository,
        verification_image=VERIFICATION_IMAGE,
        signer_identity=CANDIDATE_SIGNER,
    )
    receipt = tmp_path / "candidate-receipt.json"
    write_candidate_validation_receipt(receipt, receipt_model)
    private_key, allowed_signers = _new_signing_identity(tmp_path, label="candidate")
    signature = sign_candidate_validation_receipt(receipt, private_key)
    return _PromotionInputs(
        candidate=candidate,
        metadata=metadata,
        registry=registry,
        ledger=ledger,
        repository=repository,
        receipt=receipt,
        signature=signature,
        allowed_signers=allowed_signers,
        private_key=private_key,
    )


@pytest.fixture(scope="module")
def promotion_template(tmp_path_factory: pytest.TempPathFactory) -> _PromotionInputs:
    """Build the costly exact signed candidate receipt only once."""
    root = tmp_path_factory.mktemp("corpus-promotion-template")
    patch = pytest.MonkeyPatch()
    try:
        return _build_inputs(root, patch)
    finally:
        patch.undo()


@pytest.fixture
def promotion_inputs(
    promotion_template: _PromotionInputs,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> _PromotionInputs:
    """Clone an independently mutable input set from one signed exact template."""
    _patch_machine_environment(monkeypatch)
    template_root = promotion_template.candidate.parent
    clone_root = tmp_path / "inputs"
    shutil.copytree(template_root, clone_root)

    def rebased(path: Path) -> Path:
        return clone_root / path.relative_to(template_root)

    return _PromotionInputs(
        candidate=rebased(promotion_template.candidate),
        metadata=rebased(promotion_template.metadata),
        registry=rebased(promotion_template.registry),
        ledger=rebased(promotion_template.ledger),
        repository=rebased(promotion_template.repository),
        receipt=rebased(promotion_template.receipt),
        signature=rebased(promotion_template.signature),
        allowed_signers=rebased(promotion_template.allowed_signers),
        private_key=rebased(promotion_template.private_key),
    )


def _promote(
    inputs: _PromotionInputs,
    output: Path,
    *,
    signature: Path | None = None,
    allowed_signers: Path | None = None,
    candidate_root: Path | None = None,
    metadata_file: Path | None = None,
) -> CandidatePromotionStatement:
    """Invoke the public promotion builder with concise test defaults."""
    return promote_candidate_corpus(
        candidate_root=candidate_root or inputs.candidate,
        metadata_file=metadata_file or inputs.metadata,
        canary_registry=inputs.registry,
        access_ledger=inputs.ledger,
        candidate_receipt=inputs.receipt,
        candidate_receipt_signature=signature or inputs.signature,
        candidate_allowed_signers=allowed_signers or inputs.allowed_signers,
        candidate_signer_identity=CANDIDATE_SIGNER,
        repository=inputs.repository,
        verification_image=VERIFICATION_IMAGE,
        promotion_signer_identity=PROMOTION_SIGNER,
        output_directory=output,
    )


def test_promotes_only_split_and_binds_all_derived_hashes(
    promotion_inputs: _PromotionInputs,
    tmp_path: Path,
) -> None:
    """The signed receipt permits only byte-local split changes with exact commitments."""
    before = _tree_files(promotion_inputs.candidate)
    output = tmp_path / "sealed-package"

    statement = _promote(promotion_inputs, output)

    sealed_root = output / SEALED_CORPUS_DIRECTORY
    after = _tree_files(sealed_root)
    assert set(after) == set(before)
    for relative_path, candidate_bytes in before.items():
        if relative_path.endswith("/manifest.yaml"):
            assert candidate_bytes.count(b"benchmark_split: candidate") == 1
            assert after[relative_path] == candidate_bytes.replace(
                b"benchmark_split: candidate",
                b"benchmark_split: sealed",
            )
        else:
            assert after[relative_path] == candidate_bytes

    receipt_sha256 = hashlib.sha256(promotion_inputs.receipt.read_bytes()).hexdigest()
    sealed_scenarios = discover_scenarios(sealed_root)
    sealed_hash = corpus_hash(sealed_scenarios)
    assert statement.candidate_receipt_sha256 == receipt_sha256
    assert statement.sealed_corpus_hash == sealed_hash
    assert statement.docker_client_sha256 == DOCKER_RUNTIME.client_sha256
    assert statement.docker_runtime_fingerprint_sha256 == DOCKER_RUNTIME.fingerprint_sha256
    assert statement.sealed_source_snapshot_sha256 == (
        _inventory_tree(sealed_root).inventory_sha256
    )

    sizes = {
        item["scenario_id"]: RepositorySize(item["repository_size"])
        for item in yaml.safe_load(promotion_inputs.metadata.read_text(encoding="utf-8"))[
            "scenarios"
        ]
    }
    sealed_receipts = {
        scenario.id: _sha256_json(
            {
                "scenario_id": scenario.id,
                "scenario_artifact_sha256": scenario_hash(scenario),
                "sealed_corpus_hash": sealed_hash,
                "stinger_commit": COMMIT,
                "verification_image_id": IMAGE_ID,
                "verification_image_policy_sha256": (
                    canonical_verification_image_policy_sha256(compiled_verification_image_policy())
                ),
                "validation_contract": SEALED_VALIDATION_CONTRACT,
            }
        )
        for scenario in sealed_scenarios
    }
    records = _sealed_record_stubs(sealed_scenarios, sizes, sealed_receipts)
    assert statement.sealed_scenario_artifact_inventory_sha256 == (
        sealed_scenario_artifact_inventory_sha256(records)
    )
    assert statement.sealed_validation_inventory_sha256 == (
        candidate_validation_inventory_sha256(records)
    )

    extended_ledger = (output / SEALED_ACCESS_LEDGER_FILE).read_bytes()
    registry_sha256 = hashlib.sha256(promotion_inputs.registry.read_bytes()).hexdigest()
    ledger_root, event_count, _ = _verify_access_ledger(
        extended_ledger,
        candidate_corpus_hash=sealed_hash,
        canary_registry_sha256=registry_sha256,
    )
    final_event = json.loads(extended_ledger.splitlines()[-1])
    assert event_count == 2
    assert ledger_root == statement.sealed_access_log_root_sha256
    assert final_event["event_hash"] == statement.sealed_access_log_root_sha256
    assert (
        final_event["transformation_inventory_sha256"] == statement.transformation_inventory_sha256
    )
    assert json.loads((output / PROMOTION_STATEMENT_FILE).read_text(encoding="utf-8")) == (
        statement.model_dump(mode="json")
    )


def test_output_package_is_atomic_and_never_overwritten(
    promotion_inputs: _PromotionInputs,
    tmp_path: Path,
) -> None:
    """A complete existing package remains byte-exact after a repeated invocation."""
    output = tmp_path / "sealed-package"
    _promote(promotion_inputs, output)
    first_inventory = _inventory_tree(output)

    with pytest.raises(CandidatePromotionError, match="already exists"):
        _promote(promotion_inputs, output)

    assert _inventory_tree(output) == first_inventory


@pytest.mark.parametrize("tamper", ["candidate", "metadata"])
def test_rejects_source_or_metadata_drift_after_signed_validation(
    promotion_inputs: _PromotionInputs,
    tmp_path: Path,
    tamper: str,
) -> None:
    """Post-signature source and private declaration drift both fail closed."""
    if tamper == "candidate":
        manifest = next(promotion_inputs.candidate.glob("*/manifest.yaml"))
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                "Private prompt",
                "Tampered prompt",
                1,
            ),
            encoding="utf-8",
        )
    else:
        promotion_inputs.metadata.write_bytes(promotion_inputs.metadata.read_bytes() + b"\n")
    output = tmp_path / "sealed-package"

    with pytest.raises(CandidatePromotionError):
        _promote(promotion_inputs, output)

    assert not output.exists()


@pytest.mark.parametrize("failure", ["tampered-receipt", "wrong-trust"])
def test_rejects_wrong_signature_or_trust(
    promotion_inputs: _PromotionInputs,
    tmp_path: Path,
    failure: str,
) -> None:
    """Detached candidate authorization is exact-byte and exact-trust bound."""
    allowed_signers = promotion_inputs.allowed_signers
    if failure == "tampered-receipt":
        promotion_inputs.receipt.write_bytes(promotion_inputs.receipt.read_bytes() + b" ")
    else:
        _, allowed_signers = _new_signing_identity(tmp_path, label="wrong")
    output = tmp_path / "sealed-package"

    with pytest.raises(CandidatePromotionError, match="authorization failed"):
        _promote(
            promotion_inputs,
            output,
            allowed_signers=allowed_signers,
        )

    assert not output.exists()


def test_public_builders_expose_no_sandbox_factory_injection() -> None:
    """No caller can replace the canonical Docker sandbox with a favorable fake."""
    candidate_signature = inspect.signature(build_candidate_validation_receipt)
    promotion_signature = inspect.signature(promote_candidate_corpus)
    assert "_sandbox_factory" not in candidate_signature.parameters
    assert "sandbox_factory" not in promotion_signature.parameters
    with pytest.raises(TypeError, match="_sandbox_factory"):
        candidate_signature.bind_partial(_sandbox_factory=object())
    with pytest.raises(TypeError, match="sandbox_factory"):
        promotion_signature.bind_partial(sandbox_factory=object())


def test_sealed_validation_sandbox_receives_only_immutable_image_id(
    promotion_inputs: _PromotionInputs,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Promotion executes the resolved image id, never the caller's mutable tag."""
    scenarios = discover_scenarios(promotion_inputs.candidate)
    observed_images: list[str] = []

    class RecordingSandbox:
        """Minimal test double below the public promotion boundary."""

        def __init__(self, *, isolation: object, image: str) -> None:
            del isolation
            observed_images.append(image)

        def preflight_benchmark(self, _repository: Path) -> None:
            return

    monkeypatch.setattr(promotion_module, "Sandbox", RecordingSandbox)
    monkeypatch.setattr(
        promotion_module,
        "verify_docker_runtime",
        lambda expected: expected,
    )
    monkeypatch.setattr(promotion_module, "validate_scenario", _accept_validation)

    receipts = promotion_module._validate_sealed_snapshot(
        scenarios,
        sealed_corpus_hash="f" * 64,
        stinger_commit=COMMIT,
        verification_image_id=IMAGE_ID,
        repository=promotion_inputs.repository,
        verification_image_policy_sha256=canonical_verification_image_policy_sha256(
            compiled_verification_image_policy()
        ),
        docker_runtime=DOCKER_RUNTIME,
    )

    assert observed_images == [IMAGE_ID]
    assert len(receipts) == 120


def test_rejects_validation_failure_and_leaves_no_partial_package(
    promotion_inputs: _PromotionInputs,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """One failed scenario validity contract aborts and removes the temporary package."""
    monkeypatch.setattr(candidate_module, "validate_scenario", _reject_validation)
    output = tmp_path / "sealed-package"

    with pytest.raises(CandidatePromotionError, match="verification failed"):
        _promote(promotion_inputs, output)

    assert not output.exists()
    assert not list(tmp_path.glob(".sealed-package.*"))


def test_rejects_symlink_candidate_root(
    promotion_inputs: _PromotionInputs,
    tmp_path: Path,
) -> None:
    """A convenience alias cannot substitute for the directly validated source root."""
    alias = tmp_path / "candidate-alias"
    alias.symlink_to(promotion_inputs.candidate, target_is_directory=True)
    output = tmp_path / "sealed-package"

    with pytest.raises(CandidatePromotionError, match="input is invalid"):
        _promote(promotion_inputs, output, candidate_root=alias)

    assert not output.exists()


def test_rejects_unsafe_symlink_inside_candidate_tree(
    promotion_inputs: _PromotionInputs,
    tmp_path: Path,
) -> None:
    """No symlink node may enter the supposedly exact private source snapshot."""
    unsafe_link = next(promotion_inputs.candidate.iterdir()) / "unsafe-link"
    unsafe_link.symlink_to(promotion_inputs.metadata)
    output = tmp_path / "sealed-package"

    with pytest.raises(CandidatePromotionError, match="verification failed"):
        _promote(promotion_inputs, output)

    assert not output.exists()
