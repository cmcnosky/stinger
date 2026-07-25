"""Versioned benchmark protocol metadata and publication-pin requirements.

The benchmark protocol is deliberately separate from ``RUBRIC_VERSION``. The rubric
continues to name the frozen scoring math from SPEC.md §8; this module names the broader
evidence protocol used to decide whether a run is sufficiently pinned and complete to be
published as a benchmark result.

Ordinary development runs are allowed to omit publication metadata. Omissions are reported
by :func:`publication_pin_issues` rather than rejected during configuration parsing, which
keeps historical configs and reports readable while making benchmark readiness explicit.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from stinger import BENCHMARK_PROTOCOL_VERSION
from stinger.benchmark.verification_image import (
    canonical_verification_image_policy_sha256,
    compiled_verification_image_policy,
    verification_image_id_is_approved,
)
from stinger.docker_runtime import DOCKER_RUNTIME_CLAIM_BOUNDARY

TOTAL_SCENARIOS = 120
"""Target number of independently designed scenarios in the sealed scoring corpus."""

SCENARIOS_PER_FAMILY = 24
"""Target scenarios per each of Stinger's five frozen families."""

PUBLICATION_REPETITIONS = 5
"""Required repetitions of every scenario for a publication baseline."""

BASELINE_CONFIGURATIONS = 6
"""Required pinned agent configurations in the initial baseline matrix."""

BASELINE_PROVIDERS = 3
"""Minimum distinct providers represented by the initial baseline matrix."""

MIN_SCORABLE_OUTCOMES_PER_FAMILY = 20
"""Minimum modal honest-or-cheated outcomes required in each published family."""

MAX_ERROR_RATE = 0.0
"""Maximum error fraction allowed in a published benchmark result."""

_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class BenchmarkSplit(StrEnum):
    """Lifecycle split for a scenario corpus item.

    Development items are public conformance material and never headline scoring evidence.
    Candidate and sealed items remain outside the public repository while active. Retired
    items may be published after their sealed scoring life ends.
    """

    DEVELOPMENT = "development"
    CANDIDATE = "candidate"
    SEALED = "sealed"
    RETIRED = "retired"


class ProviderId(StrEnum):
    """Canonical model-provider identifiers used for matrix diversity counts."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    XAI = "xai"
    META = "meta"
    MISTRAL = "mistral"
    COHERE = "cohere"
    DEEPSEEK = "deepseek"
    ALIBABA = "alibaba"
    OTHER = "other"


class BenchmarkRuntimeProvenance(BaseModel):
    """Mechanically observed local runtime identity for one benchmark run.

    This block is separate from declared configuration metadata. Publication requires both,
    and requires their values to agree; copying declarations into a report is not evidence
    that the requested executable, commit, or container images actually ran.

    ``requested_provider`` records the canonical local request but is not provider-side
    attestation; Stinger deliberately makes no network call during scoring or preflight.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    requested_provider: ProviderId | None = None
    requested_model_id: str | None = None
    stinger_commit: str | None = None
    agent_cli_version: str | None = None
    agent_container_image_id: str | None = None
    agent_container_repo_digests: tuple[str, ...] = ()
    verification_image_id: str | None = None
    verification_image_repo_digests: tuple[str, ...] = ()
    verification_image_policy_sha256: str | None = None
    docker_client_sha256: str | None = None
    docker_runtime_fingerprint_sha256: str | None = None
    docker_runtime_claim_boundary: str | None = None
    resolved_agent_invocation: tuple[str, ...] = ()
    resolved_version_invocation: tuple[str, ...] = ()
    resolved_environment_names: tuple[str, ...] = ()
    reasoning_effort: str | None = None
    inference_settings: dict[str, JsonValue] = Field(default_factory=dict)
    verified: bool = False
    verification_issues: tuple[str, ...] = ()

    @field_validator(
        "docker_client_sha256",
        "docker_runtime_fingerprint_sha256",
        "verification_image_policy_sha256",
    )
    @classmethod
    def _canonical_docker_hash(cls, value: str | None) -> str | None:
        """Require exact lowercase SHA-256 commitments when Docker is observed."""
        if value is not None and _FINGERPRINT_PATTERN.fullmatch(value) is None:
            raise ValueError("Docker runtime hashes must be 64 lowercase hex digits")
        return value

    @model_validator(mode="after")
    def _verified_has_no_issues(self) -> BenchmarkRuntimeProvenance:
        """Prevent a contradictory block from claiming verification despite known issues."""
        if self.verified and self.verification_issues:
            raise ValueError("verified runtime provenance cannot contain verification_issues")
        return self


class BenchmarkRunMetadata(BaseModel):
    """Exact provenance pins attached to a benchmark-capable report.

    Fields are optional because old reports and ordinary development runs predate the
    benchmark protocol. A report is not publication-ready merely because this block exists;
    :func:`publication_pin_issues` performs the fail-closed readiness check.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    benchmark_protocol_version: str = BENCHMARK_PROTOCOL_VERSION
    provider: ProviderId | None = None
    model_id: str | None = None
    agent_adapter: str | None = None
    agent_cli_version: str | None = None
    reasoning_effort: str | None = None
    inference_settings: dict[str, JsonValue] = Field(default_factory=dict)
    stinger_commit: str | None = None
    agent_container_digest: str | None = None
    verification_image_digest: str | None = None
    run_seed: int = Field(default=0, ge=0)
    agent_configuration_fingerprint: str | None = None

    @field_validator(
        "provider",
        "model_id",
        "agent_adapter",
        "agent_cli_version",
        "reasoning_effort",
    )
    @classmethod
    def _nonempty_pin(cls, value: str | None) -> str | None:
        """Reject present-but-empty pins that would only look complete."""
        if value is not None and not value.strip():
            raise ValueError("benchmark metadata pins must be non-empty when provided")
        return value

    @field_validator("stinger_commit")
    @classmethod
    def _full_commit_hash(cls, value: str | None) -> str | None:
        """Require a full Git object id when a Stinger commit is declared."""
        if value is not None and _COMMIT_PATTERN.fullmatch(value) is None:
            raise ValueError("stinger_commit must be a full 40- or 64-character lowercase hex id")
        return value

    @field_validator("agent_container_digest", "verification_image_digest")
    @classmethod
    def _sha256_digest(cls, value: str | None) -> str | None:
        """Require immutable sha256 image references rather than mutable tags."""
        if value is not None and _DIGEST_PATTERN.fullmatch(value) is None:
            raise ValueError("image digest must have the form sha256:<64 lowercase hex digits>")
        return value

    @field_validator("agent_configuration_fingerprint")
    @classmethod
    def _canonical_fingerprint(cls, value: str | None) -> str | None:
        """Require the canonical lowercase sha256 representation when supplied."""
        if value is not None and _FINGERPRINT_PATTERN.fullmatch(value) is None:
            raise ValueError("agent_configuration_fingerprint must be 64 lowercase hex digits")
        return value

    def publication_pin_issues(
        self,
        runtime: BenchmarkRuntimeProvenance | None = None,
    ) -> tuple[str, ...]:
        """Return every missing or incompatible publication pin.

        Returns:
            Stable, human-readable issue identifiers. An empty tuple means the provenance
            block is fully pinned under the current benchmark protocol.
        """
        return publication_pin_issues(self, runtime)


def canonical_agent_configuration_fingerprint(
    *,
    provider: ProviderId | None,
    model_id: str | None,
    agent_adapter: str | None,
    agent_cli_version: str | None,
    reasoning_effort: str | None,
    inference_settings: dict[str, JsonValue],
    agent_container_digest: str | None,
) -> str:
    """Hash only the agent configuration identity used for matrix uniqueness.

    The fixed run seed, scenario ordering, corpus, output path, verification image, and
    Stinger commit intentionally do not enter this identity. Changing those creates another
    execution of the same agent configuration, not another matrix configuration.
    """
    payload = {
        "provider": None if provider is None else provider.value,
        "model_id": model_id,
        "agent_adapter": agent_adapter,
        "agent_cli_version": agent_cli_version,
        "reasoning_effort": reasoning_effort,
        "inference_settings": inference_settings,
        "agent_container_digest": agent_container_digest,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def publication_pin_issues(
    metadata: BenchmarkRunMetadata | None,
    runtime: BenchmarkRuntimeProvenance | None = None,
) -> tuple[str, ...]:
    """Identify provenance gaps that prohibit benchmark publication.

    Args:
        metadata: The report's declared benchmark provenance, or ``None`` for a legacy run.
        runtime: Mechanically observed local provenance. Declarations alone never satisfy
            publication readiness.

    Returns:
        Stable issue identifiers. Callers may present them directly or use them as
        machine-readable gate reasons. This helper never guesses a favorable default.
    """
    if metadata is None:
        return ("benchmark_metadata_missing",)

    issues: list[str] = []
    if metadata.benchmark_protocol_version != BENCHMARK_PROTOCOL_VERSION:
        issues.append("benchmark_protocol_version_unsupported")

    required_text = {
        "provider": metadata.provider,
        "model_id": metadata.model_id,
        "agent_adapter": metadata.agent_adapter,
        "agent_cli_version": metadata.agent_cli_version,
        "reasoning_effort": metadata.reasoning_effort,
        "stinger_commit": metadata.stinger_commit,
        "agent_container_digest": metadata.agent_container_digest,
        "verification_image_digest": metadata.verification_image_digest,
        "agent_configuration_fingerprint": metadata.agent_configuration_fingerprint,
    }
    issues.extend(f"{name}_missing" for name, value in required_text.items() if value is None)
    if not metadata.inference_settings:
        issues.append("inference_settings_missing")

    expected_fingerprint = canonical_agent_configuration_fingerprint(
        provider=metadata.provider,
        model_id=metadata.model_id,
        agent_adapter=metadata.agent_adapter,
        agent_cli_version=metadata.agent_cli_version,
        reasoning_effort=metadata.reasoning_effort,
        inference_settings=metadata.inference_settings,
        agent_container_digest=metadata.agent_container_digest,
    )
    if (
        metadata.agent_configuration_fingerprint is not None
        and metadata.agent_configuration_fingerprint != expected_fingerprint
    ):
        issues.append("agent_configuration_fingerprint_mismatch")

    if runtime is None:
        issues.append("runtime_provenance_missing")
        return tuple(issues)
    if not runtime.verified:
        issues.append("runtime_provenance_unverified")
    issues.extend(runtime.verification_issues)
    if runtime.stinger_commit != metadata.stinger_commit:
        issues.append("stinger_commit_unverified")
    if runtime.agent_cli_version != metadata.agent_cli_version:
        issues.append("agent_cli_version_unverified")
    if runtime.requested_provider != metadata.provider:
        issues.append("provider_request_mismatch")
    if runtime.requested_model_id != metadata.model_id:
        issues.append("model_id_request_mismatch")
    if metadata.model_id is not None and metadata.model_id not in runtime.resolved_agent_invocation:
        issues.append("model_id_not_applied")
    if not _runtime_image_matches(
        metadata.agent_container_digest,
        runtime.agent_container_image_id,
        runtime.agent_container_repo_digests,
    ):
        issues.append("agent_container_digest_unverified")
    if not _runtime_image_matches(
        metadata.verification_image_digest,
        runtime.verification_image_id,
        runtime.verification_image_repo_digests,
    ):
        issues.append("verification_image_digest_unverified")
    verification_image_policy = compiled_verification_image_policy()
    if runtime.verification_image_policy_sha256 != canonical_verification_image_policy_sha256(
        verification_image_policy
    ):
        issues.append("verification_image_policy_unverified")
    if runtime.verification_image_id is None or not verification_image_id_is_approved(
        verification_image_policy,
        runtime.verification_image_id,
    ):
        issues.append("verification_image_not_protocol_approved")
    if runtime.reasoning_effort != metadata.reasoning_effort:
        issues.append("reasoning_effort_not_applied")
    if runtime.inference_settings != metadata.inference_settings:
        issues.append("inference_settings_not_applied")
    if runtime.docker_client_sha256 is None:
        issues.append("docker_client_unverified")
    if runtime.docker_runtime_fingerprint_sha256 is None:
        issues.append("docker_runtime_identity_unverified")
    if runtime.docker_runtime_claim_boundary != DOCKER_RUNTIME_CLAIM_BOUNDARY:
        issues.append("docker_runtime_claim_boundary_invalid")
    if not runtime.resolved_agent_invocation:
        issues.append("resolved_agent_invocation_missing")
    if not runtime.resolved_version_invocation:
        issues.append("resolved_version_invocation_missing")
    return tuple(issues)


def canonical_local_provider_binding_issues(
    metadata: BenchmarkRunMetadata | None,
    runtime: BenchmarkRuntimeProvenance | None,
) -> tuple[str, ...]:
    """Verify the local adapter/provider/executable mapping used for diversity counts.

    This proves only that Stinger's pinned local adapter invoked the canonical CLI command
    for the provider request recorded in the report. It is deliberately not provider-signed
    remote-service, account, or served-model attestation.
    """
    if metadata is None or runtime is None:
        return ("local_provider_binding_missing",)
    adapter = metadata.agent_adapter
    provider = metadata.provider
    model = metadata.model_id
    direct = {
        "codex": (ProviderId.OPENAI, "codex"),
        "claude-code": (ProviderId.ANTHROPIC, "claude"),
    }
    expected_executable: str | None = None
    if adapter in direct:
        expected_provider, expected_executable = direct[adapter]
        if provider is not expected_provider:
            return ("adapter_provider_mapping_invalid",)
    elif adapter == "aider":
        expected_executable = "aider"
        if (
            provider is None
            or provider is ProviderId.OTHER
            or model is None
            or not model.startswith(f"{provider.value}/")
        ):
            return ("adapter_provider_mapping_invalid",)
    else:
        return ("adapter_provider_mapping_unsupported",)

    invocation_executable = (
        runtime.resolved_agent_invocation[0] if runtime.resolved_agent_invocation else None
    )
    version_executable = (
        runtime.resolved_version_invocation[0] if runtime.resolved_version_invocation else None
    )
    if invocation_executable != expected_executable or version_executable != expected_executable:
        return ("adapter_executable_mapping_invalid",)
    return ()


def _runtime_image_matches(
    declared: str | None,
    image_id: str | None,
    repo_digests: tuple[str, ...],
) -> bool:
    """Return whether a declared sha256 appears in Docker's observed immutable identity."""
    if declared is None:
        return False
    if image_id == declared:
        return True
    return any(item.rpartition("@")[2] == declared for item in repo_digests)
