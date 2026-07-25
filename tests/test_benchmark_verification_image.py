"""Hostile tests for the signed Protocol 2 verification-image policy."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import stinger.benchmark.verification_image as policy_module
import stinger.harness.sandbox as sandbox_module
from stinger.benchmark.verification_image import (
    APPROVED_LINUX_AMD64_VERIFICATION_IMAGE_CONFIG_ID,
    APPROVED_LINUX_AMD64_VERIFICATION_IMAGE_ID,
    APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_CONFIG_ID,
    APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID,
    VERIFICATION_IMAGE_SOURCE_INVENTORY_SHA256,
    VERIFICATION_IMAGE_SOURCE_PATHS,
    VerificationImagePolicy,
    VerificationImagePolicyError,
    canonical_verification_image_policy_sha256,
    compiled_verification_image_policy,
    verification_image_source_inventory_sha256,
    verify_approved_verification_image,
    verify_verification_image_policy,
)
from stinger.docker_runtime import DockerImageIdentity, DockerRuntimeIdentity
from stinger.harness.sandbox import Isolation, Sandbox, SandboxError

REPOSITORY = Path(__file__).resolve().parents[1]


def _runtime() -> DockerRuntimeIdentity:
    return DockerRuntimeIdentity(
        client_path="/fixed/docker",
        client_sha256="a" * 64,
        client_version="29.0.0",
        context_name="fixture",
        context_endpoint="unix:///fixture.sock",
        context_endpoint_sha256="b" * 64,
        server_platform="fixture",
        server_version="29.0.0",
        server_api_version="1.50",
        server_os="linux",
        server_arch="arm64",
    )


def _copy_sources(destination: Path) -> None:
    for relative_path in VERIFICATION_IMAGE_SOURCE_PATHS:
        source = REPOSITORY / relative_path
        target = destination / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def test_compiled_policy_binds_the_exact_checked_in_build_sources() -> None:
    policy = compiled_verification_image_policy()

    assert verification_image_source_inventory_sha256(REPOSITORY) == (
        VERIFICATION_IMAGE_SOURCE_INVENTORY_SHA256
    )
    assert verify_verification_image_policy(REPOSITORY, policy) == (
        VERIFICATION_IMAGE_SOURCE_INVENTORY_SHA256
    )
    assert canonical_verification_image_policy_sha256(policy) == (
        "4dad36298c73364d8924ffe909a4673b4199a5e49455b387d6e9f1f67fd9e0c4"
    )


def test_checked_in_build_recipe_preserves_the_observed_image_identity() -> None:
    dockerfile = (REPOSITORY / "docker" / "runner.Dockerfile").read_text(encoding="utf-8")
    assert "--no-compile" in dockerfile
    assert "PYTHONDONTWRITEBYTECODE=1" in dockerfile

    for workflow_path in (
        REPOSITORY / ".github" / "workflows" / "ci.yml",
        REPOSITORY / ".github" / "workflows" / "stinger.yml",
    ):
        workflow = workflow_path.read_text(encoding="utf-8")
        assert "docker buildx build --no-cache --provenance=false" in workflow
        assert "--build-arg SOURCE_DATE_EPOCH=0" in workflow
        assert "type=docker,rewrite-timestamp=true" in workflow


def test_source_drift_fails_before_image_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _copy_sources(tmp_path)
    dockerfile = tmp_path / "docker" / "runner.Dockerfile"
    dockerfile.write_bytes(dockerfile.read_bytes() + b"\n# drift\n")
    inspected = False

    def inspect(*_args: object, **_kwargs: object) -> DockerImageIdentity:
        nonlocal inspected
        inspected = True
        raise AssertionError("source drift must fail before Docker image inspection")

    monkeypatch.setattr(policy_module, "inspect_docker_image_identity", inspect)
    with pytest.raises(VerificationImagePolicyError, match="build-source inventory"):
        verify_approved_verification_image(
            repository=tmp_path,
            image="attacker:latest",
            policy=compiled_verification_image_policy(),
        )
    assert inspected is False


def test_policy_drift_fails_before_image_inspection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = compiled_verification_image_policy().model_copy(
        update={"claim_boundary": "weaker operator assertion"}
    )
    inspected = False

    def inspect(*_args: object, **_kwargs: object) -> DockerImageIdentity:
        nonlocal inspected
        inspected = True
        raise AssertionError("policy drift must fail before Docker image inspection")

    monkeypatch.setattr(policy_module, "inspect_docker_image_identity", inspect)
    with pytest.raises(VerificationImagePolicyError, match="differs"):
        verify_approved_verification_image(
            repository=REPOSITORY,
            image="attacker:latest",
            policy=policy,
        )
    assert inspected is False


def test_platform_identity_representations_are_closed_and_ordered() -> None:
    compiled = compiled_verification_image_policy().model_dump(mode="json")
    original = compiled["approved_images"][0]["identities"]

    for invalid_identities in (tuple(reversed(original)), original[:1]):
        payload = compiled_verification_image_policy().model_dump(mode="json")
        payload["approved_images"][0]["identities"] = invalid_identities
        with pytest.raises(ValueError, match="manifest then config"):
            VerificationImagePolicy.model_validate(payload)


@pytest.mark.parametrize(
    ("image_id", "operating_system", "architecture", "error"),
    [
        ("sha256:" + "f" * 64, "linux", "arm64", "not approved"),
        (APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID, "linux", "s390x", "platform"),
    ],
)
def test_arbitrary_image_or_platform_is_rejected(
    image_id: str,
    operating_system: str,
    architecture: str,
    error: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime()
    monkeypatch.setattr(policy_module, "observe_docker_runtime", lambda: runtime)
    monkeypatch.setattr(
        policy_module,
        "verify_docker_runtime",
        lambda expected: expected,
    )
    monkeypatch.setattr(
        policy_module,
        "inspect_docker_image_identity",
        lambda _image, *, runtime: DockerImageIdentity(
            image_id=image_id,
            repo_digests=(),
            operating_system=operating_system,
            architecture=architecture,
        ),
    )

    with pytest.raises(VerificationImagePolicyError, match=error):
        verify_approved_verification_image(
            repository=REPOSITORY,
            image="attacker:latest",
            policy=compiled_verification_image_policy(),
        )


def test_approved_platform_and_image_return_policy_bound_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime()
    identity = DockerImageIdentity(
        image_id=APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID,
        repo_digests=("example.invalid/runner@sha256:" + "c" * 64,),
        operating_system="linux",
        architecture="arm64",
    )
    monkeypatch.setattr(policy_module, "observe_docker_runtime", lambda: runtime)
    monkeypatch.setattr(
        policy_module,
        "verify_docker_runtime",
        lambda expected: expected,
    )
    monkeypatch.setattr(
        policy_module,
        "inspect_docker_image_identity",
        lambda _image, *, runtime: identity,
    )

    verified = verify_approved_verification_image(
        repository=REPOSITORY,
        image="stinger-runner:protocol2",
        policy=compiled_verification_image_policy(),
    )

    assert verified.image == identity
    assert verified.docker_runtime == runtime
    assert verified.source_inventory_sha256 == VERIFICATION_IMAGE_SOURCE_INVENTORY_SHA256
    assert verified.policy_sha256 == canonical_verification_image_policy_sha256(
        compiled_verification_image_policy()
    )


def test_compiled_policy_approves_the_exact_ci_amd64_image() -> None:
    policy = compiled_verification_image_policy()

    assert tuple(
        (
            item.platform,
            tuple((identity.representation, identity.image_id) for identity in item.identities),
        )
        for item in policy.approved_images
    ) == (
        (
            "linux/amd64",
            (
                ("oci-manifest-digest", APPROVED_LINUX_AMD64_VERIFICATION_IMAGE_ID),
                (
                    "oci-image-config-digest",
                    APPROVED_LINUX_AMD64_VERIFICATION_IMAGE_CONFIG_ID,
                ),
            ),
        ),
        (
            "linux/arm64",
            (
                ("oci-manifest-digest", APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID),
                (
                    "oci-image-config-digest",
                    APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_CONFIG_ID,
                ),
            ),
        ),
    )


@pytest.mark.parametrize(
    "image_id",
    [
        APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID,
        APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_CONFIG_ID,
    ],
)
def test_both_docker_store_identity_representations_are_approved(
    image_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime()
    identity = DockerImageIdentity(
        image_id=image_id,
        repo_digests=(),
        operating_system="linux",
        architecture="arm64",
    )
    monkeypatch.setattr(policy_module, "observe_docker_runtime", lambda: runtime)
    monkeypatch.setattr(policy_module, "verify_docker_runtime", lambda expected: expected)
    monkeypatch.setattr(
        policy_module,
        "inspect_docker_image_identity",
        lambda _image, *, runtime: identity,
    )

    verified = verify_approved_verification_image(
        repository=REPOSITORY,
        image="stinger-runner:protocol2",
        policy=compiled_verification_image_policy(),
    )
    assert verified.image.image_id == image_id


def test_benchmark_sandbox_rejects_policy_before_starting_a_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sandbox_module,
        "verify_approved_verification_image",
        lambda **_kwargs: (_ for _ in ()).throw(VerificationImagePolicyError("unapproved image")),
    )
    container_started = False

    def run(*_args: object, **_kwargs: object) -> object:
        nonlocal container_started
        container_started = True
        raise AssertionError("a rejected verifier must never start a container")

    monkeypatch.setattr(sandbox_module, "_run_sandbox_process", run)
    sandbox = Sandbox(isolation=Isolation.DOCKER, image="attacker:latest")

    with pytest.raises(SandboxError, match="policy rejected"):
        sandbox.preflight_benchmark(REPOSITORY)
    assert container_started is False
