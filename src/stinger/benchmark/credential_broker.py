"""Credential-isolation identities shared by sealed agent execution and evidence.

Protocol 2 agents receive only a short-lived broker lease and a fixed broker base URL.
The provider credential remains in a separate broker container on a dual-homed topology;
the untrusted agent joins only a fresh Docker-internal network.  This module contains the
closed configuration and receipt schemas plus deterministic identity helpers.  It does not
open a socket or read a credential value.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from stinger.benchmark.protocol import (
    CredentialBrokerProviderRoute,
    ProviderId,
    canonical_credential_isolation_policy_sha256,
    compiled_credential_isolation_policy,
)

BROKER_ALIAS: Literal["stinger-credential-broker"] = "stinger-credential-broker"
BROKER_PORT = 8765
BROKER_SERVER_SOURCE = "src/stinger/credential_broker_server.py"
BROKER_RAW_CREDENTIAL_ENV = "STINGER_BROKER_RAW_CREDENTIAL"
BROKER_LEASE_ENV = "STINGER_BROKER_LEASE"
BROKER_CONFIG_PATH = "/run/stinger-broker/config.json"
BROKER_AUDIT_PATH = "/evidence/audit.jsonl"
BROKER_SERVER_PATH = "/opt/stinger/credential_broker_server.py"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class CredentialBrokerConfiguration(BaseModel):
    """Non-secret operator selection for the trusted external broker image."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    image: str
    image_digest: str

    @field_validator("image")
    @classmethod
    def _canonical_image(cls, value: str) -> str:
        if not value or value != value.strip() or "\x00" in value:
            raise ValueError("credential broker image must be canonical and nonblank")
        return value

    @field_validator("image_digest")
    @classmethod
    def _immutable_image(cls, value: str) -> str:
        if _IMAGE_ID.fullmatch(value) is None:
            raise ValueError("credential broker image_digest must be an immutable sha256 ID")
        return value


class CredentialIsolationInvocationReceipt(BaseModel):
    """Canonical proof emitted after one brokered agent invocation and cleanup."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    format_version: Literal["1"] = "1"
    policy_sha256: str
    broker_configuration_sha256: str
    allowed_destination_inventory_sha256: str
    resolved_upstream_address_inventory_sha256: str
    agent_projection_inventory_sha256: str
    broker_source_inventory_sha256: str
    broker_image_id: str
    broker_image_repo_digests: tuple[str, ...] = ()
    docker_client_sha256: str
    docker_runtime_fingerprint_sha256: str
    agent_container_id_sha256: str
    broker_container_id_sha256: str
    internal_network_id_sha256: str
    internal_network_name_sha256: str
    outbound_network_id_sha256: str
    outbound_network_name_sha256: str
    broker_lease_sha256: str
    agent_command_inventory_sha256: str
    agent_environment_inventory_sha256: str
    agent_mount_inventory_sha256: str
    agent_image_credential_scan_sha256: str
    agent_container_runtime_inventory_sha256: str
    broker_container_runtime_inventory_sha256: str
    network_attachment_inventory_sha256: str
    broker_audit_sha256: str
    request_count: int
    rejection_count: int
    agent_environment_names: tuple[str, ...]
    agent_read_only_mounts: tuple[str, ...] = ()
    agent_network_mode: Literal["fresh-docker-internal-network-only"]
    agent_bridge_gateway: Literal["isolated-no-host-interface"]
    agent_dns: Literal["embedded-broker-alias-with-loopback-only-upstream"]
    broker_alias: Literal["stinger-credential-broker"]
    raw_provider_credential_exposed: Literal[False]
    broker_bypass_path_present: Literal[False]
    unapproved_egress_path_present: Literal[False]
    agent_container_cleanup_verified: Literal[True]
    broker_container_cleanup_verified: Literal[True]
    internal_network_cleanup_verified: Literal[True]
    outbound_network_cleanup_verified: Literal[True]

    @field_validator(
        "policy_sha256",
        "broker_configuration_sha256",
        "allowed_destination_inventory_sha256",
        "resolved_upstream_address_inventory_sha256",
        "agent_projection_inventory_sha256",
        "broker_source_inventory_sha256",
        "docker_client_sha256",
        "docker_runtime_fingerprint_sha256",
        "agent_container_id_sha256",
        "broker_container_id_sha256",
        "internal_network_id_sha256",
        "internal_network_name_sha256",
        "outbound_network_id_sha256",
        "outbound_network_name_sha256",
        "broker_lease_sha256",
        "agent_command_inventory_sha256",
        "agent_environment_inventory_sha256",
        "agent_mount_inventory_sha256",
        "agent_image_credential_scan_sha256",
        "agent_container_runtime_inventory_sha256",
        "broker_container_runtime_inventory_sha256",
        "network_attachment_inventory_sha256",
        "broker_audit_sha256",
    )
    @classmethod
    def _canonical_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("credential-isolation receipt hashes must be lowercase sha256")
        return value

    @field_validator("broker_image_id")
    @classmethod
    def _broker_image(cls, value: str) -> str:
        if _IMAGE_ID.fullmatch(value) is None:
            raise ValueError("credential-isolation broker image must be immutable")
        return value

    @field_validator("request_count", "rejection_count")
    @classmethod
    def _nonnegative_count(cls, value: int) -> int:
        if value < 0:
            raise ValueError("credential-isolation counts must be nonnegative")
        return value

    @field_validator("agent_environment_names")
    @classmethod
    def _canonical_environment_names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if (
            not value
            or value != tuple(sorted(value))
            or len(value) != len(set(value))
            or any(_ENVIRONMENT_NAME.fullmatch(name) is None for name in value)
        ):
            raise ValueError("agent credential projection environment names are not canonical")
        return value

    @model_validator(mode="after")
    def _closed_projection(self) -> CredentialIsolationInvocationReceipt:
        if self.agent_read_only_mounts:
            raise ValueError("credential-isolated agents cannot receive extra read-only mounts")
        if (
            self.internal_network_id_sha256 == self.outbound_network_id_sha256
            or self.internal_network_name_sha256 == self.outbound_network_name_sha256
        ):
            raise ValueError("agent and broker outbound network identities must be distinct")
        if self.rejection_count:
            raise ValueError("a rejected broker request fails the invocation closed")
        if self.request_count < 1:
            raise ValueError("credential-isolation evidence must cover a provider request")
        return self


def canonical_json_bytes(value: object) -> bytes:
    """Encode one non-secret evidence value in the repository's canonical JSON form."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def sha256_bytes(value: bytes) -> str:
    """Return the lowercase SHA-256 of exact bytes."""
    return hashlib.sha256(value).hexdigest()


def provider_route(
    agent_adapter: str,
    provider: ProviderId | None,
) -> CredentialBrokerProviderRoute:
    """Resolve one adapter/provider pair from the signed closed allowlist."""
    for route in compiled_credential_isolation_policy().provider_routes:
        if route.agent_adapter == agent_adapter and route.provider is provider:
            return route
    raise ValueError("adapter/provider pair is not approved for credential brokering")


def agent_environment_names(route: CredentialBrokerProviderRoute) -> tuple[str, ...]:
    """Return the exact environment names projected into an untrusted agent."""
    names: list[str] = [route.agent_credential_environment_name]
    if route.agent_base_url_environment_name is not None:
        names.append(route.agent_base_url_environment_name)
    return tuple(sorted(names))


def agent_base_url_config_argv(route: CredentialBrokerProviderRoute) -> tuple[str, ...]:
    """Return the signed non-secret CLI routing override, when the adapter needs one."""
    if route.agent_base_url_config_key is None:
        return ()
    encoded = json.dumps(route.agent_base_url, sort_keys=True, separators=(",", ":"))
    return ("--config", f"{route.agent_base_url_config_key}={encoded}")


def broker_source_inventory_sha256(repository: Path) -> str:
    """Hash every policy-listed broker source without following a symlink."""
    root = repository.resolve(strict=True)
    sources: dict[str, Path] = {}
    for relative_path in _broker_source_paths():
        source = root / relative_path
        try:
            source.resolve(strict=True).relative_to(root)
        except (OSError, ValueError) as exc:
            raise ValueError("credential-broker source is unavailable") from exc
        sources[relative_path] = source
    return broker_source_file_inventory_sha256(sources)


def broker_source_file_inventory_sha256(sources: Mapping[str, Path]) -> str:
    """Hash policy-listed broker files at source-tree or installed-package locations."""
    expected_paths = _broker_source_paths()
    if set(sources) != set(expected_paths):
        raise ValueError("credential-broker source inventory paths are not exact")
    files: list[dict[str, object]] = []
    for relative_path in expected_paths:
        source = sources[relative_path]
        try:
            metadata = source.lstat()
            resolved = source.resolve(strict=True)
        except OSError as exc:
            raise ValueError("credential-broker source is unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("credential-broker source must be a regular nonsymlink file")
        descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                metadata.st_dev,
                metadata.st_ino,
            ):
                raise ValueError("credential-broker source changed while opening")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                content = stream.read()
            after = os.fstat(descriptor)
            if (after.st_dev, after.st_ino, after.st_size) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
            ):
                raise ValueError("credential-broker source changed while reading")
        finally:
            os.close(descriptor)
        files.append(
            {
                "path": relative_path,
                "sha256": sha256_bytes(content),
                "size": len(content),
            }
        )
    return sha256_bytes(canonical_json_bytes({"files": files}))


def _broker_source_paths() -> tuple[str, ...]:
    paths = compiled_credential_isolation_policy().broker_source_paths
    if paths != (BROKER_SERVER_SOURCE,):
        raise ValueError("credential-broker source policy is not supported")
    return paths


def credential_identity_payloads(
    *,
    route: CredentialBrokerProviderRoute,
    broker: CredentialBrokerConfiguration,
    api_key_env: str,
    source_inventory_sha256: str,
) -> tuple[str, str, str, str]:
    """Derive policy, config, destination, and minimal-projection commitments."""
    if _ENVIRONMENT_NAME.fullmatch(api_key_env) is None:
        raise ValueError("provider credential environment name is invalid")
    policy_sha256 = canonical_credential_isolation_policy_sha256(
        compiled_credential_isolation_policy()
    )
    configuration_sha256 = sha256_bytes(
        canonical_json_bytes(
            {
                "format_version": "1",
                "provider_route": route.model_dump(mode="json"),
                "broker_image_digest": broker.image_digest,
                "broker_source_inventory_sha256": source_inventory_sha256,
                "provider_credential_source": {
                    "kind": "host-environment",
                    "name": api_key_env,
                },
            }
        )
    )
    destinations_sha256 = sha256_bytes(
        canonical_json_bytes(
            {
                "upstream_https_origin": route.upstream_https_origin,
                "path_mappings": [item.model_dump(mode="json") for item in route.path_mappings],
            }
        )
    )
    projection_sha256 = sha256_bytes(
        canonical_json_bytes(
            {
                "arguments": (
                    []
                    if route.agent_base_url_config_key is None
                    else [
                        {
                            "kind": "codex-cli-config",
                            "name": route.agent_base_url_config_key,
                            "value": route.agent_base_url,
                        }
                    ]
                ),
                "files": [],
                "mounts": [],
                "environment": [
                    {
                        "name": api_key_env,
                        "value_kind": "opaque-per-invocation-broker-lease",
                    },
                    *(
                        []
                        if route.agent_base_url_environment_name is None
                        else [
                            {
                                "name": route.agent_base_url_environment_name,
                                "value": route.agent_base_url,
                            }
                        ]
                    ),
                ],
            }
        )
    )
    return policy_sha256, configuration_sha256, destinations_sha256, projection_sha256


__all__ = [
    "BROKER_ALIAS",
    "BROKER_AUDIT_PATH",
    "BROKER_CONFIG_PATH",
    "BROKER_LEASE_ENV",
    "BROKER_PORT",
    "BROKER_RAW_CREDENTIAL_ENV",
    "BROKER_SERVER_PATH",
    "BROKER_SERVER_SOURCE",
    "CredentialBrokerConfiguration",
    "CredentialIsolationInvocationReceipt",
    "agent_base_url_config_argv",
    "agent_environment_names",
    "broker_source_inventory_sha256",
    "canonical_json_bytes",
    "credential_identity_payloads",
    "provider_route",
    "sha256_bytes",
]
