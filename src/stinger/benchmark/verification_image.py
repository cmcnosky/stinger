"""Signed Protocol 2 policy for benchmark verification-container bytes.

The verification image executes held-out checks and deterministic detectors. Merely
recording whichever image an operator supplied would therefore let an arbitrary image forge
favourable verification results. Protocol 2 closes that gap by signing both the exact
Docker build-source inventory and a platform-keyed allowlist of locally observed immutable
image identities. Each platform record names the OCI manifest digest and the OCI image
config digest from the same byte-identical exported builds. Docker's containerd image store
reports the former as ``.Id``; classic Docker Engine reports the latter. The image config
also binds the root filesystem through its ordered DiffIDs.

This policy proves only that Stinger observed approved bytes through the bounded Docker
client/daemon boundary. It is not a reproducible-build proof, registry attestation, TPM
statement, or protection from an administrator-controlled daemon.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from stinger.docker_runtime import (
    DockerImageIdentity,
    DockerRuntimeError,
    DockerRuntimeIdentity,
    inspect_docker_image_identity,
    observe_docker_runtime,
    verify_docker_runtime,
)

VERIFICATION_IMAGE_POLICY_FORMAT_VERSION = "1"
VERIFICATION_IMAGE_POLICY_CLAIM_BOUNDARY = (
    "signed exact Dockerfile and dependency-lock bytes plus platform-keyed OCI manifest "
    "and image-config digests from the same byte-identical exported builds, matched to the "
    "immutable ID observed through Stinger's fixed Docker client and daemon-reported "
    "identity; not universal reproducible-build, registry-attestation, TPM, physical-host, daemon "
    "anti-fabrication, or administrator-integrity proof"
)
VERIFICATION_IMAGE_SOURCE_PATHS = (
    "docker/runner.Dockerfile",
    "docker/runner-requirements.lock",
)
VERIFICATION_IMAGE_SOURCE_INVENTORY_SHA256 = (
    "3e4b0259a51bbd792a14fe0c950e452c249e5f6eea9b635083157b20f652109e"
)
APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID = (
    "sha256:7e3c9970f164032e35dd2fbc82ddf712279fac2d3e631578988ed61d586b168e"
)
APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_CONFIG_ID = (
    "sha256:b07ecc68cec24ccc49b51e0935b0a1676f777717d1db3e2ee8d7c571f25aa1eb"
)
APPROVED_LINUX_AMD64_VERIFICATION_IMAGE_ID = (
    "sha256:0321810c35d74b13876498965ed8977bd567b62d2df5ae7e620e4202787001a2"
)
APPROVED_LINUX_AMD64_VERIFICATION_IMAGE_CONFIG_ID = (
    "sha256:15c664fc2f6e49328439770f220b930a8a55ee67f4a8ab93bf8f2960ec3790e5"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_PLATFORM = re.compile(r"^[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$")


class VerificationImagePolicyError(Exception):
    """Raised when verification-image source or runtime identity is not approved."""


class _FrozenModel(BaseModel):
    """Immutable closed schema for signed verification-image policy records."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class VerificationImageIdentityRepresentation(_FrozenModel):
    """One named immutable identity representation for the same exported image."""

    representation: Literal["oci-manifest-digest", "oci-image-config-digest"]
    image_id: str

    @field_validator("image_id")
    @classmethod
    def _immutable_image_id(cls, value: str) -> str:
        """Require one canonical sha256 identity."""
        if _IMAGE_ID.fullmatch(value) is None:
            raise ValueError("verification image identity must be an immutable sha256 digest")
        return value


class ApprovedVerificationImage(_FrozenModel):
    """Named immutable identities approved for one Docker target platform."""

    platform: str
    identities: tuple[VerificationImageIdentityRepresentation, ...]

    @field_validator("platform")
    @classmethod
    def _canonical_platform(cls, value: str) -> str:
        """Require a canonical Docker ``os/architecture`` key."""
        if _PLATFORM.fullmatch(value) is None:
            raise ValueError("verification-image platform must be canonical os/architecture")
        return value

    @model_validator(mode="after")
    def _closed_identity_representations(self) -> ApprovedVerificationImage:
        """Require both exact store-dependent identities in one canonical order."""
        representations = tuple(item.representation for item in self.identities)
        image_ids = tuple(item.image_id for item in self.identities)
        if representations != (
            "oci-manifest-digest",
            "oci-image-config-digest",
        ):
            raise ValueError(
                "verification-image identities must contain manifest then config digest"
            )
        if len(set(image_ids)) != len(image_ids):
            raise ValueError("verification-image identity digests must be distinct")
        return self


class VerificationImagePolicy(_FrozenModel):
    """Exact build-source commitment and closed platform-to-image allowlist."""

    format_version: str
    claim_boundary: str
    source_paths: tuple[str, ...]
    source_inventory_sha256: str
    approved_images: tuple[ApprovedVerificationImage, ...]

    @field_validator("format_version", "claim_boundary")
    @classmethod
    def _nonblank_text(cls, value: str) -> str:
        """Reject blank or padded policy text."""
        if not value or value != value.strip():
            raise ValueError("verification-image policy text must be canonical and nonblank")
        return value

    @field_validator("source_inventory_sha256")
    @classmethod
    def _canonical_hash(cls, value: str) -> str:
        """Require an exact lowercase source-inventory commitment."""
        if _SHA256.fullmatch(value) is None:
            raise ValueError("source inventory hash must be 64 lowercase hexadecimal characters")
        return value

    @model_validator(mode="after")
    def _closed_inventory(self) -> VerificationImagePolicy:
        """Require canonical paths and one approved image per sorted platform."""
        if self.source_paths != VERIFICATION_IMAGE_SOURCE_PATHS:
            raise ValueError("verification-image source paths do not match the closed inventory")
        platforms = tuple(item.platform for item in self.approved_images)
        if (
            not platforms
            or platforms != tuple(sorted(platforms))
            or len(set(platforms)) != len(platforms)
        ):
            raise ValueError(
                "approved verification images must contain unique, platform-sorted entries"
            )
        return self


@dataclass(frozen=True, slots=True)
class VerifiedVerificationImage:
    """One policy-approved local image observation and its trust bindings."""

    policy_sha256: str
    source_inventory_sha256: str
    image: DockerImageIdentity
    docker_runtime: DockerRuntimeIdentity


def compiled_verification_image_policy() -> VerificationImagePolicy:
    """Return the exact verification-image policy compiled into Protocol 2."""
    return VerificationImagePolicy(
        format_version=VERIFICATION_IMAGE_POLICY_FORMAT_VERSION,
        claim_boundary=VERIFICATION_IMAGE_POLICY_CLAIM_BOUNDARY,
        source_paths=VERIFICATION_IMAGE_SOURCE_PATHS,
        source_inventory_sha256=VERIFICATION_IMAGE_SOURCE_INVENTORY_SHA256,
        approved_images=(
            ApprovedVerificationImage(
                platform="linux/amd64",
                identities=(
                    VerificationImageIdentityRepresentation(
                        representation="oci-manifest-digest",
                        image_id=APPROVED_LINUX_AMD64_VERIFICATION_IMAGE_ID,
                    ),
                    VerificationImageIdentityRepresentation(
                        representation="oci-image-config-digest",
                        image_id=APPROVED_LINUX_AMD64_VERIFICATION_IMAGE_CONFIG_ID,
                    ),
                ),
            ),
            ApprovedVerificationImage(
                platform="linux/arm64",
                identities=(
                    VerificationImageIdentityRepresentation(
                        representation="oci-manifest-digest",
                        image_id=APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID,
                    ),
                    VerificationImageIdentityRepresentation(
                        representation="oci-image-config-digest",
                        image_id=APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_CONFIG_ID,
                    ),
                ),
            ),
        ),
    )


def canonical_verification_image_policy_sha256(policy: VerificationImagePolicy) -> str:
    """Hash one typed policy in deterministic JSON form."""
    payload = policy.model_dump(mode="json")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def verification_image_source_inventory_sha256(repository: Path) -> str:
    """Hash exact regular, nonsymlink Dockerfile and lock bytes under ``repository``."""
    files: list[dict[str, object]] = []
    for relative_path in VERIFICATION_IMAGE_SOURCE_PATHS:
        content = _read_policy_source(repository, relative_path)
        files.append(
            {
                "path": relative_path,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    encoded = json.dumps(
        {"files": files},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def verify_verification_image_policy(
    repository: Path,
    policy: VerificationImagePolicy,
) -> str:
    """Require the signed policy and local source bytes to match compiled Protocol 2."""
    compiled = compiled_verification_image_policy()
    if policy != compiled:
        raise VerificationImagePolicyError(
            "signed verification-image policy differs from this implementation"
        )
    observed_source = verification_image_source_inventory_sha256(repository)
    if observed_source != policy.source_inventory_sha256:
        raise VerificationImagePolicyError(
            "verification-image build-source inventory differs from the signed policy"
        )
    return observed_source


def verify_approved_verification_image(
    *,
    repository: Path,
    image: str,
    policy: VerificationImagePolicy,
    docker_runtime: DockerRuntimeIdentity | None = None,
) -> VerifiedVerificationImage:
    """Verify source bytes, Docker runtime, target platform, and immutable image ID."""
    source_inventory = verify_verification_image_policy(repository, policy)
    try:
        runtime = (
            observe_docker_runtime()
            if docker_runtime is None
            else verify_docker_runtime(docker_runtime)
        )
        identity = inspect_docker_image_identity(image, runtime=runtime)
        verify_docker_runtime(runtime)
    except DockerRuntimeError as exc:
        raise VerificationImagePolicyError(
            "verification image or Docker runtime could not be proved"
        ) from exc
    approved = {item.platform: item.identities for item in policy.approved_images}
    expected_identities = approved.get(identity.platform)
    if expected_identities is None:
        raise VerificationImagePolicyError(
            f"verification-image platform {identity.platform!r} is not approved"
        )
    if identity.image_id not in {item.image_id for item in expected_identities}:
        raise VerificationImagePolicyError(
            "verification image ID is not approved for its observed platform"
        )
    return VerifiedVerificationImage(
        policy_sha256=canonical_verification_image_policy_sha256(policy),
        source_inventory_sha256=source_inventory,
        image=identity,
        docker_runtime=runtime,
    )


def verification_image_id_is_approved(
    policy: VerificationImagePolicy,
    image_id: str,
) -> bool:
    """Return whether an immutable ID appears in the closed platform allowlist."""
    return any(
        identity.image_id == image_id
        for approved in policy.approved_images
        for identity in approved.identities
    )


def _read_policy_source(repository: Path, relative_path: str) -> bytes:
    """Read one bounded policy source without following a symlink."""
    root = repository.resolve(strict=True)
    candidate = root / relative_path
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise VerificationImagePolicyError(
            "verification-image build source is unavailable"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise VerificationImagePolicyError(
            "verification-image build source must be a regular nonsymlink file"
        )
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise VerificationImagePolicyError(
            "verification-image build source escaped the repository"
        ) from exc
    descriptor = os.open(
        resolved,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (
            opened.st_dev,
            opened.st_ino,
        ) != (
            metadata.st_dev,
            metadata.st_ino,
        ):
            raise VerificationImagePolicyError(
                "verification-image build source changed while opening"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read()
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ):
            raise VerificationImagePolicyError(
                "verification-image build source changed while reading"
            )
        return content
    except OSError as exc:
        raise VerificationImagePolicyError(
            "verification-image build source could not be read"
        ) from exc
    finally:
        os.close(descriptor)
