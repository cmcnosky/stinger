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
from typing import Literal

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


CredentialIsolationFormatVersion = Literal["1"]

CREDENTIAL_ISOLATION_CLAIM_BOUNDARY = (
    "mechanically observed Docker network, broker, destination-allowlist, and minimal "
    "agent-projection evidence showing that raw provider credentials remained outside the "
    "networked agent container; not provider-side, host-administrator, kernel-integrity, "
    "or physical-hardware attestation"
)
"""The deliberately narrow claim made by credential-isolation runtime evidence."""


class CredentialBrokerPathMapping(BaseModel):
    """One exact agent-facing route and its fixed provider upstream."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_path: str
    upstream_path: str
    methods: tuple[Literal["POST"], ...]

    @field_validator("agent_path", "upstream_path")
    @classmethod
    def _absolute_canonical_path(cls, value: str) -> str:
        if not value.startswith("/") or "?" in value or "#" in value or ".." in value:
            raise ValueError("credential-broker paths must be canonical absolute paths")
        return value

    @model_validator(mode="after")
    def _nonempty_methods(self) -> CredentialBrokerPathMapping:
        if not self.methods:
            raise ValueError("credential-broker path mapping must allow at least one method")
        return self


class CredentialBrokerProviderRoute(BaseModel):
    """Complete signed destination and header mapping for one supported adapter."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: ProviderId
    agent_adapter: Literal["codex", "claude-code"]
    agent_base_url_environment_name: Literal["ANTHROPIC_BASE_URL"] | None = None
    agent_base_url_config_key: Literal["openai_base_url"] | None = None
    agent_credential_environment_name: Literal["OPENAI_API_KEY", "ANTHROPIC_API_KEY"]
    agent_base_url: str
    upstream_https_origin: str
    path_mappings: tuple[CredentialBrokerPathMapping, ...]
    forwarded_agent_headers: tuple[str, ...]
    stripped_agent_headers: tuple[str, ...]
    inbound_lease_header: Literal["authorization", "x-api-key"]
    inbound_lease_scheme: Literal["bearer", "raw"]
    injected_auth_header: Literal["authorization", "x-api-key"]
    injected_auth_scheme: Literal["bearer", "raw"]

    @model_validator(mode="after")
    def _canonical_route(self) -> CredentialBrokerProviderRoute:
        expected = {
            ProviderId.OPENAI: (
                "codex",
                None,
                "openai_base_url",
                "OPENAI_API_KEY",
                "authorization",
                "bearer",
                "authorization",
                "bearer",
            ),
            ProviderId.ANTHROPIC: (
                "claude-code",
                "ANTHROPIC_BASE_URL",
                None,
                "ANTHROPIC_API_KEY",
                "x-api-key",
                "raw",
                "x-api-key",
                "raw",
            ),
        }
        if self.provider not in expected:
            raise ValueError("credential broker supports only protocol-approved providers")
        if (
            self.agent_adapter,
            self.agent_base_url_environment_name,
            self.agent_base_url_config_key,
            self.agent_credential_environment_name,
            self.inbound_lease_header,
            self.inbound_lease_scheme,
            self.injected_auth_header,
            self.injected_auth_scheme,
        ) != expected[self.provider]:
            raise ValueError("credential-broker provider mapping is contradictory")
        if not self.agent_base_url.startswith("http://stinger-credential-broker:8765/"):
            raise ValueError("agent base URL must name the isolated broker endpoint")
        if not self.upstream_https_origin.startswith("https://"):
            raise ValueError("provider upstream must be an exact HTTPS origin")
        if self.upstream_https_origin.count("/") != 2:
            raise ValueError("provider upstream must not contain a path")
        if not self.path_mappings:
            raise ValueError("credential-broker provider route must map at least one path")
        if len({item.agent_path for item in self.path_mappings}) != len(self.path_mappings):
            raise ValueError("credential-broker agent paths must be unique")
        for values in (self.forwarded_agent_headers, self.stripped_agent_headers):
            if any(not value or value != value.lower() for value in values):
                raise ValueError("credential-broker header names must be lowercase")
            if len(set(values)) != len(values):
                raise ValueError("credential-broker header names must be unique")
        if set(self.forwarded_agent_headers) & set(self.stripped_agent_headers):
            raise ValueError("credential-broker forwarded and stripped headers overlap")
        return self


class CredentialIsolationPolicy(BaseModel):
    """Closed Protocol 2 policy for brokering every credentialed agent request."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    format_version: CredentialIsolationFormatVersion
    claim_boundary: str
    raw_provider_credential_location: Literal["external-broker-only"]
    agent_network: Literal["fresh-docker-internal-network-only"]
    agent_bridge_gateway: Literal["isolated-no-host-interface"]
    agent_dns: Literal["embedded-broker-alias-with-loopback-only-upstream"]
    agent_projection: Literal["broker-origin-and-opaque-session-only"]
    destination_binding: Literal["exact-provider-scheme-host-port-path-allowlist"]
    request_policy: Literal[
        "fixed-upstream-no-connect-no-redirect-strip-agent-auth-and-proxy-headers"
    ]
    broker_identity: Literal["source-inventory-and-immutable-image"]
    broker_source_paths: tuple[str, ...]
    broker_source_inventory_sha256: str
    agent_image_final_rootfs_credential_scan_required: Literal[True]
    agent_image_credential_encoding_policy: Literal["raw-hex-base64-urlsafe-base64-percent"]
    agent_image_config_home_policy: Literal["declared-agent-config-home-must-be-empty"]
    agent_image_prohibited_credential_path_suffixes: tuple[str, ...]
    docker_runtime_identity_required: Literal[True]
    per_invocation_receipt_required: Literal[True]
    provider_routes: tuple[CredentialBrokerProviderRoute, ...]

    @field_validator("claim_boundary")
    @classmethod
    def _fixed_claim_boundary(cls, value: str) -> str:
        if value != CREDENTIAL_ISOLATION_CLAIM_BOUNDARY:
            raise ValueError("credential-isolation claim boundary is fixed")
        return value

    @field_validator("broker_source_inventory_sha256")
    @classmethod
    def _source_inventory_hash(cls, value: str) -> str:
        if _FINGERPRINT_PATTERN.fullmatch(value) is None:
            raise ValueError("broker source inventory hash must be 64 lowercase hex digits")
        return value

    @field_validator("broker_source_paths")
    @classmethod
    def _source_paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values or tuple(sorted(set(values))) != values:
            raise ValueError("broker source paths must be a sorted unique nonempty inventory")
        if any(value.startswith("/") or ".." in value.split("/") for value in values):
            raise ValueError("broker source paths must be repository-relative")
        return values

    @field_validator("agent_image_prohibited_credential_path_suffixes")
    @classmethod
    def _credential_path_suffixes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values or tuple(sorted(set(values))) != values:
            raise ValueError("credential path suffixes must be sorted, unique, and nonempty")
        if any(not value.startswith("/") or value != value.lower() for value in values):
            raise ValueError("credential path suffixes must be lowercase absolute suffixes")
        return values

    @model_validator(mode="after")
    def _closed_provider_set(self) -> CredentialIsolationPolicy:
        if tuple(route.provider for route in self.provider_routes) != (
            ProviderId.OPENAI,
            ProviderId.ANTHROPIC,
        ):
            raise ValueError("credential-isolation policy provider routes are fixed")
        return self


def compiled_credential_isolation_policy() -> CredentialIsolationPolicy:
    """Return the one credential-isolation policy compiled into Protocol 2."""
    return CredentialIsolationPolicy(
        format_version="1",
        claim_boundary=CREDENTIAL_ISOLATION_CLAIM_BOUNDARY,
        raw_provider_credential_location="external-broker-only",
        agent_network="fresh-docker-internal-network-only",
        agent_bridge_gateway="isolated-no-host-interface",
        agent_dns="embedded-broker-alias-with-loopback-only-upstream",
        agent_projection="broker-origin-and-opaque-session-only",
        destination_binding="exact-provider-scheme-host-port-path-allowlist",
        request_policy=("fixed-upstream-no-connect-no-redirect-strip-agent-auth-and-proxy-headers"),
        broker_identity="source-inventory-and-immutable-image",
        broker_source_paths=("src/stinger/credential_broker_server.py",),
        broker_source_inventory_sha256=(
            "de20acc5ac798d64d2fe1278daf4c409fad634e6f2112e20d0d083a644b48539"
        ),
        agent_image_final_rootfs_credential_scan_required=True,
        agent_image_credential_encoding_policy="raw-hex-base64-urlsafe-base64-percent",
        agent_image_config_home_policy="declared-agent-config-home-must-be-empty",
        agent_image_prohibited_credential_path_suffixes=(
            "/.aws/credentials",
            "/.azure/accesstokens.json",
            "/.azure/azureprofile.json",
            "/.codex/auth.json",
            "/.config/gcloud/application_default_credentials.json",
            "/.config/gh/hosts.yml",
            "/.config/github-copilot/apps.json",
            "/.config/github-copilot/hosts.json",
            "/.docker/config.json",
            "/.env",
            "/.git-credentials",
            "/.netrc",
            "/.npmrc",
            "/.pypirc",
            "/etc/claude-code/managed-settings.json",
            "/etc/claude/managed-settings.json",
            "/etc/codex/config.toml",
        ),
        docker_runtime_identity_required=True,
        per_invocation_receipt_required=True,
        provider_routes=(
            CredentialBrokerProviderRoute(
                provider=ProviderId.OPENAI,
                agent_adapter="codex",
                agent_base_url_config_key="openai_base_url",
                agent_credential_environment_name="OPENAI_API_KEY",
                agent_base_url="http://stinger-credential-broker:8765/openai/v1",
                upstream_https_origin="https://api.openai.com:443",
                path_mappings=(
                    CredentialBrokerPathMapping(
                        agent_path="/openai/v1/responses",
                        upstream_path="/v1/responses",
                        methods=("POST",),
                    ),
                    CredentialBrokerPathMapping(
                        agent_path="/openai/v1/responses/compact",
                        upstream_path="/v1/responses/compact",
                        methods=("POST",),
                    ),
                ),
                forwarded_agent_headers=(
                    "accept",
                    "content-type",
                    "openai-beta",
                    "user-agent",
                ),
                stripped_agent_headers=(
                    "authorization",
                    "cookie",
                    "host",
                    "proxy-authorization",
                    "x-api-key",
                ),
                inbound_lease_header="authorization",
                inbound_lease_scheme="bearer",
                injected_auth_header="authorization",
                injected_auth_scheme="bearer",
            ),
            CredentialBrokerProviderRoute(
                provider=ProviderId.ANTHROPIC,
                agent_adapter="claude-code",
                agent_base_url_environment_name="ANTHROPIC_BASE_URL",
                agent_credential_environment_name="ANTHROPIC_API_KEY",
                agent_base_url="http://stinger-credential-broker:8765/anthropic",
                upstream_https_origin="https://api.anthropic.com:443",
                path_mappings=(
                    CredentialBrokerPathMapping(
                        agent_path="/anthropic/v1/messages",
                        upstream_path="/v1/messages",
                        methods=("POST",),
                    ),
                    CredentialBrokerPathMapping(
                        agent_path="/anthropic/v1/messages/count_tokens",
                        upstream_path="/v1/messages/count_tokens",
                        methods=("POST",),
                    ),
                ),
                forwarded_agent_headers=(
                    "accept",
                    "anthropic-beta",
                    "anthropic-version",
                    "content-type",
                    "user-agent",
                ),
                stripped_agent_headers=(
                    "authorization",
                    "cookie",
                    "host",
                    "proxy-authorization",
                    "x-api-key",
                ),
                inbound_lease_header="x-api-key",
                inbound_lease_scheme="raw",
                injected_auth_header="x-api-key",
                injected_auth_scheme="raw",
            ),
        ),
    )


def canonical_credential_isolation_policy_sha256(
    policy: CredentialIsolationPolicy,
) -> str:
    """Hash the exact closed policy embedded in the signed protocol manifest."""
    encoded = json.dumps(
        policy.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class CredentialIsolationRuntimeProvenance(BaseModel):
    """Mechanically observed identities for the external credential broker boundary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    format_version: CredentialIsolationFormatVersion = "1"
    claim_boundary: str = CREDENTIAL_ISOLATION_CLAIM_BOUNDARY
    policy_sha256: str
    broker_configuration_sha256: str
    allowed_destination_inventory_sha256: str
    agent_projection_inventory_sha256: str
    broker_source_inventory_sha256: str
    broker_image_id: str
    broker_image_repo_digests: tuple[str, ...] = ()
    docker_runtime_fingerprint_sha256: str
    verified: bool = False
    verification_issues: tuple[str, ...] = ()

    @field_validator(
        "policy_sha256",
        "broker_configuration_sha256",
        "allowed_destination_inventory_sha256",
        "agent_projection_inventory_sha256",
        "broker_source_inventory_sha256",
        "docker_runtime_fingerprint_sha256",
    )
    @classmethod
    def _canonical_hash(cls, value: str) -> str:
        if _FINGERPRINT_PATTERN.fullmatch(value) is None:
            raise ValueError("credential-isolation hashes must be 64 lowercase hex digits")
        return value

    @field_validator("broker_image_id")
    @classmethod
    def _immutable_broker_image(cls, value: str) -> str:
        if _DIGEST_PATTERN.fullmatch(value) is None:
            raise ValueError("broker_image_id must be an immutable sha256 image identity")
        return value

    @field_validator("claim_boundary")
    @classmethod
    def _credential_claim_boundary(cls, value: str) -> str:
        if value != CREDENTIAL_ISOLATION_CLAIM_BOUNDARY:
            raise ValueError("credential-isolation claim boundary is fixed")
        return value

    @model_validator(mode="after")
    def _verified_has_no_issues(self) -> CredentialIsolationRuntimeProvenance:
        if self.verified and self.verification_issues:
            raise ValueError(
                "verified credential-isolation provenance cannot contain verification_issues"
            )
        return self


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
    credential_isolation: CredentialIsolationRuntimeProvenance | None = None
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
    credential_isolation_policy_sha256: str | None = None
    credential_broker_configuration_sha256: str | None = None
    credential_allowed_destination_inventory_sha256: str | None = None
    credential_agent_projection_inventory_sha256: str | None = None
    credential_broker_source_inventory_sha256: str | None = None
    credential_broker_image_digest: str | None = None

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

    @field_validator(
        "agent_container_digest",
        "verification_image_digest",
        "credential_broker_image_digest",
    )
    @classmethod
    def _sha256_digest(cls, value: str | None) -> str | None:
        """Require immutable sha256 image references rather than mutable tags."""
        if value is not None and _DIGEST_PATTERN.fullmatch(value) is None:
            raise ValueError("image digest must have the form sha256:<64 lowercase hex digits>")
        return value

    @field_validator(
        "agent_configuration_fingerprint",
        "credential_isolation_policy_sha256",
        "credential_broker_configuration_sha256",
        "credential_allowed_destination_inventory_sha256",
        "credential_agent_projection_inventory_sha256",
        "credential_broker_source_inventory_sha256",
    )
    @classmethod
    def _canonical_fingerprint(cls, value: str | None) -> str | None:
        """Require the canonical lowercase sha256 representation when supplied."""
        if value is not None and _FINGERPRINT_PATTERN.fullmatch(value) is None:
            raise ValueError("benchmark evidence hashes must be 64 lowercase hex digits")
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
    credential_broker_configuration_sha256: str | None = None,
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
    if credential_broker_configuration_sha256 is not None:
        payload["credential_broker_configuration_sha256"] = credential_broker_configuration_sha256
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
        "credential_isolation_policy_sha256": (metadata.credential_isolation_policy_sha256),
        "credential_broker_configuration_sha256": (metadata.credential_broker_configuration_sha256),
        "credential_allowed_destination_inventory_sha256": (
            metadata.credential_allowed_destination_inventory_sha256
        ),
        "credential_agent_projection_inventory_sha256": (
            metadata.credential_agent_projection_inventory_sha256
        ),
        "credential_broker_source_inventory_sha256": (
            metadata.credential_broker_source_inventory_sha256
        ),
        "credential_broker_image_digest": metadata.credential_broker_image_digest,
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
        credential_broker_configuration_sha256=(metadata.credential_broker_configuration_sha256),
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
    isolation = runtime.credential_isolation
    if isolation is None:
        issues.append("credential_isolation_runtime_missing")
        return tuple(issues)
    if not isolation.verified:
        issues.append("credential_isolation_runtime_unverified")
    issues.extend(isolation.verification_issues)
    credential_policy = compiled_credential_isolation_policy()
    expected_policy_sha256 = canonical_credential_isolation_policy_sha256(credential_policy)
    if metadata.credential_isolation_policy_sha256 != expected_policy_sha256:
        issues.append("credential_isolation_policy_not_protocol_approved")
    if isolation.policy_sha256 != expected_policy_sha256:
        issues.append("credential_isolation_policy_unverified")
    if isolation.broker_configuration_sha256 != metadata.credential_broker_configuration_sha256:
        issues.append("credential_isolation_configuration_mismatch")
    if (
        isolation.allowed_destination_inventory_sha256
        != metadata.credential_allowed_destination_inventory_sha256
    ):
        issues.append("credential_allowed_destinations_mismatch")
    if (
        isolation.agent_projection_inventory_sha256
        != metadata.credential_agent_projection_inventory_sha256
    ):
        issues.append("credential_agent_projection_mismatch")
    if (
        isolation.broker_source_inventory_sha256
        != metadata.credential_broker_source_inventory_sha256
    ):
        issues.append("credential_broker_source_mismatch")
    if (
        metadata.credential_broker_source_inventory_sha256
        != credential_policy.broker_source_inventory_sha256
        or isolation.broker_source_inventory_sha256
        != credential_policy.broker_source_inventory_sha256
    ):
        issues.append("credential_broker_source_not_protocol_approved")
    if not _runtime_image_matches(
        metadata.credential_broker_image_digest,
        isolation.broker_image_id,
        isolation.broker_image_repo_digests,
    ):
        issues.append("credential_broker_image_identity_mismatch")
    if not verification_image_id_is_approved(
        verification_image_policy,
        isolation.broker_image_id,
    ):
        issues.append("credential_broker_image_not_protocol_approved")
    if isolation.docker_runtime_fingerprint_sha256 != runtime.docker_runtime_fingerprint_sha256:
        issues.append("credential_isolation_docker_runtime_identity_mismatch")
    if isolation.claim_boundary != CREDENTIAL_ISOLATION_CLAIM_BOUNDARY:
        issues.append("credential_isolation_claim_boundary_invalid")
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
