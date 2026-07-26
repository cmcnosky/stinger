"""Host-side controller for Protocol 2's external credential broker.

The controller is trusted harness code; the agent container is not.  It creates one fresh
Docker-internal network per invocation, starts a dual-homed fixed-origin broker, and gives
the agent only that network plus an opaque one-use lease.  The raw provider credential is
forwarded by name into the broker container only.  After the agent exits, the controller
mechanically inspects the stopped container, broker, network, mounts, and environment before
removing all three and emitting a canonical non-secret receipt.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import tarfile
import tempfile
import time
from base64 import b64encode, urlsafe_b64encode
from collections.abc import Mapping
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import quote_from_bytes
from uuid import uuid4

from stinger.benchmark.credential_broker import (
    BROKER_ALIAS,
    BROKER_AUDIT_PATH,
    BROKER_CONFIG_PATH,
    BROKER_LEASE_ENV,
    BROKER_RAW_CREDENTIAL_ENV,
    BROKER_SERVER_PATH,
    BROKER_SERVER_SOURCE,
    CredentialIsolationInvocationReceipt,
    agent_environment_names,
    broker_source_inventory_sha256,
    canonical_json_bytes,
    credential_identity_payloads,
    provider_route,
    sha256_bytes,
)
from stinger.benchmark.protocol import compiled_credential_isolation_policy
from stinger.benchmark.verification_image import (
    compiled_verification_image_policy,
    verification_image_id_is_approved,
)
from stinger.config import AgentConfig
from stinger.docker_runtime import (
    DockerRuntimeError,
    DockerRuntimeIdentity,
    inspect_docker_image,
    run_docker,
    terminate_docker_container,
    verify_docker_runtime,
)

_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_PROVIDER_SECRET_NAME = re.compile(
    r"(?:^|_)(?:API_?KEY|KEY|TOKEN|ACCESS_?TOKEN|AUTH_?TOKEN|OAUTH_?TOKEN|"
    r"SESSION_?TOKEN|CREDENTIALS?|SECRET|PASSWORD|PRIVATE_?KEY)(?:$|_)",
    re.IGNORECASE,
)
_PROXY_NAME = re.compile(r"(?:^|_)(?:HTTP|HTTPS|ALL|NO)_?PROXY$", re.IGNORECASE)
_ROUTING_NAME = re.compile(
    r"(?:^|_)(?:BASE_?URL|API_?BASE|ENDPOINT|MODEL_?PROVIDER)(?:$|_)",
    re.IGNORECASE,
)
_READY_TIMEOUT_SECONDS = 15.0
_MAX_AUDIT_BYTES = 8 * 1024 * 1024
_NETWORK_ABSENCE_OBSERVATIONS = 2
_ROOTFS_SCAN_CACHE: dict[tuple[str, str, str, str], str] = {}


class CredentialBrokerError(Exception):
    """A fail-closed broker setup, evidence, or policy failure."""


class CredentialBrokerContainmentError(RuntimeError):
    """Cleanup could not prove the credentialed broker topology absent."""


class CredentialBrokerSession:
    """One started broker and fresh internal agent network."""

    def __init__(
        self,
        config: AgentConfig,
        *,
        runtime: DockerRuntimeIdentity,
        repository: Path,
    ) -> None:
        """Validate static inputs and allocate non-secret per-invocation identities."""
        broker = config.credential_broker
        if broker is None or config.api_key_env is None:
            raise CredentialBrokerError("credential broker configuration is missing")
        try:
            route = provider_route(config.adapter, config.provider)
        except ValueError as exc:
            raise CredentialBrokerError("agent provider route is not protocol-approved") from exc
        if config.api_key_env != route.agent_credential_environment_name:
            raise CredentialBrokerError("provider credential source disagrees with broker route")
        try:
            raw_credential = os.environ[config.api_key_env]
        except KeyError as exc:
            raise CredentialBrokerError(
                f"required host credential variable {config.api_key_env!r} is not set"
            ) from exc
        if (
            len(raw_credential.encode("utf-8")) < 16
            or len(raw_credential.encode("utf-8")) > 16 * 1024
            or raw_credential != raw_credential.strip()
            or "\x00" in raw_credential
        ):
            raise CredentialBrokerError("host provider credential is not a canonical secret value")

        self._config = config
        self._broker = broker
        self._route = route
        self._runtime = runtime
        self._repository = repository.resolve(strict=True)
        self._raw_credential = raw_credential
        self._lease = secrets.token_urlsafe(32)
        if self._lease == raw_credential:
            raise CredentialBrokerError("broker lease unexpectedly equals the provider credential")
        suffix = uuid4().hex[:12]
        self.network_name = f"stinger-credential-{suffix}"
        self.broker_container_name = f"stinger-broker-{suffix}"
        self._network_id: str | None = None
        self._broker_container_id: str | None = None
        self._broker_image_id: str | None = None
        self._broker_repo_digests: tuple[str, ...] = ()
        self._broker_image_environment: dict[str, str] | None = None
        self._agent_image_id: str | None = None
        self._agent_image_entrypoint: tuple[str, ...] = ()
        self._agent_image_metadata_scanned = False
        self._agent_image_credential_scan_sha256: str | None = None
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._temporary_path: Path | None = None
        self._config_path: Path | None = None
        self._audit_path: Path | None = None
        self._configuration_bytes: bytes | None = None
        self._source_inventory_sha256: str | None = None
        self._identity_hashes: tuple[str, str, str, str] | None = None
        self._image_environment: dict[str, str] | None = None
        self._started = False
        self._finished = False
        self._network_creation_attempted = False
        self._broker_quiesced = False

    @property
    def agent_environment_names(self) -> tuple[str, ...]:
        """Return the exact environment names projected into the agent."""
        return agent_environment_names(self._route)

    @property
    def agent_image_id(self) -> str:
        """Return the immutable agent image inspected before topology creation."""
        if self._agent_image_id is None:
            raise CredentialBrokerError("agent image identity is incomplete")
        return self._agent_image_id

    def agent_environment(self) -> dict[str, str]:
        """Return a minimal Docker-client source environment containing no raw key."""
        if not self._started or self._finished:
            raise CredentialBrokerError("credential broker session is not active")
        environment: dict[str, str] = {self._route.agent_credential_environment_name: self._lease}
        if self._route.agent_base_url_environment_name is not None:
            environment[self._route.agent_base_url_environment_name] = self._route.agent_base_url
        return environment

    def verify_agent_inputs(
        self,
        *,
        workdir: Path,
        expected_command: tuple[str, ...],
    ) -> None:
        """Reject provider-credential exposure before any networked container exists."""
        if self._started or self._finished or not expected_command:
            raise CredentialBrokerError("credential-isolation input preflight is unavailable")
        variants = _credential_variants(self._raw_credential.encode("utf-8"))
        if any(
            _contains_credential_variant(argument.encode("utf-8"), variants)
            for argument in expected_command
        ):
            raise CredentialBrokerError(
                "provider credential or a reversible encoding appeared in the agent command"
            )
        self._reject_credential_in_workdir(workdir, variants)

    def start(self) -> CredentialBrokerSession:
        """Create and mechanically verify the broker topology before agent launch."""
        if self._started or self._finished:
            raise CredentialBrokerError("credential broker session cannot be reused")
        try:
            verify_docker_runtime(self._runtime)
            self._verify_static_identity()
            self._prepare_evidence_files()
            self._create_internal_network()
            self._start_broker_container()
            self._connect_and_verify_broker()
            self._wait_until_ready()
            verify_docker_runtime(self._runtime)
        except BaseException as exc:
            self._cleanup_after_failure(exc)
            if isinstance(exc, CredentialBrokerError):
                raise
            if isinstance(exc, Exception):
                raise CredentialBrokerError("credential broker setup failed closed") from exc
            raise
        self._started = True
        return self

    def finish(
        self,
        *,
        agent_container_name: str,
        agent_image: str,
        workdir: Path,
        transcript: str,
        exit_code: int,
        expected_command: tuple[str, ...],
    ) -> CredentialIsolationInvocationReceipt:
        """Inspect exact runtime state, clean up, and return one non-secret receipt."""
        if not self._started or self._finished:
            raise CredentialBrokerError("credential broker session is not active")
        failure: BaseException | None = None
        observed: dict[str, Any] | None = None
        broker_runtime_inventory: dict[str, Any] | None = None
        audit_bytes: bytes | None = None
        counts: tuple[int, int] | None = None
        try:
            observed = self._inspect_agent_container(
                agent_container_name=agent_container_name,
                agent_image=agent_image,
                workdir=workdir,
                exit_code=exit_code,
                expected_command=expected_command,
            )
            broker_runtime_inventory = self._verify_broker_runtime_state()
            self._verify_internal_network_membership()
            self._quiesce_broker()
            audit_bytes, counts = self._load_and_verify_audit()
            self._verify_static_bytes_unchanged()
            self._reject_raw_credential_artifacts(transcript, workdir, audit_bytes)
        except BaseException as exc:
            failure = exc

        cleanup_failure = self._cleanup(agent_container_name=agent_container_name)
        self._finished = True
        if cleanup_failure is not None:
            raise CredentialBrokerContainmentError(
                "credential broker cleanup could not be mechanically verified"
            ) from cleanup_failure
        if failure is not None:
            if isinstance(failure, CredentialBrokerError):
                raise failure
            if isinstance(failure, Exception):
                raise CredentialBrokerError(
                    "credential-isolation evidence failed closed"
                ) from failure
            raise failure
        if (
            observed is None
            or broker_runtime_inventory is None
            or audit_bytes is None
            or counts is None
        ):
            raise CredentialBrokerError("credential-isolation evidence is incomplete")

        policy_sha256, configuration_sha256, destinations_sha256, projection_sha256 = (
            self._require_identity_hashes()
        )
        agent_container_id = _required_text(observed, "agent_container_id")
        broker_container_id = self._require_broker_container_id()
        network_id = self._require_network_id()
        environment_inventory = observed["environment_inventory"]
        mount_inventory = observed["mount_inventory"]
        attachment_inventory = observed["network_attachment_inventory"]
        request_count, rejection_count = counts
        return CredentialIsolationInvocationReceipt(
            policy_sha256=policy_sha256,
            broker_configuration_sha256=configuration_sha256,
            allowed_destination_inventory_sha256=destinations_sha256,
            agent_projection_inventory_sha256=projection_sha256,
            broker_source_inventory_sha256=self._require_source_inventory(),
            broker_image_id=self._require_broker_image_id(),
            broker_image_repo_digests=self._broker_repo_digests,
            docker_client_sha256=self._runtime.client_sha256,
            docker_runtime_fingerprint_sha256=self._runtime.fingerprint_sha256,
            agent_container_id_sha256=sha256_bytes(agent_container_id.encode("ascii")),
            broker_container_id_sha256=sha256_bytes(broker_container_id.encode("ascii")),
            internal_network_id_sha256=sha256_bytes(network_id.encode("ascii")),
            internal_network_name_sha256=sha256_bytes(self.network_name.encode("ascii")),
            broker_lease_sha256=sha256_bytes(self._lease.encode("utf-8")),
            agent_command_inventory_sha256=sha256_bytes(
                canonical_json_bytes(observed["command_inventory"])
            ),
            agent_environment_inventory_sha256=sha256_bytes(
                canonical_json_bytes(environment_inventory)
            ),
            agent_mount_inventory_sha256=sha256_bytes(canonical_json_bytes(mount_inventory)),
            agent_image_credential_scan_sha256=(self._require_agent_image_credential_scan_sha256()),
            agent_container_runtime_inventory_sha256=sha256_bytes(
                canonical_json_bytes(observed["runtime_identity_inventory"])
            ),
            broker_container_runtime_inventory_sha256=sha256_bytes(
                canonical_json_bytes(broker_runtime_inventory)
            ),
            network_attachment_inventory_sha256=sha256_bytes(
                canonical_json_bytes(attachment_inventory)
            ),
            broker_audit_sha256=sha256_bytes(audit_bytes),
            request_count=request_count,
            rejection_count=rejection_count,
            agent_environment_names=self.agent_environment_names,
            agent_read_only_mounts=(),
            agent_network_mode="fresh-docker-internal-network-only",
            agent_bridge_gateway="isolated-no-host-interface",
            agent_dns="embedded-broker-alias-with-loopback-only-upstream",
            broker_alias=BROKER_ALIAS,
            raw_provider_credential_exposed=False,
            broker_bypass_path_present=False,
            unapproved_egress_path_present=False,
            agent_container_cleanup_verified=True,
            broker_container_cleanup_verified=True,
            internal_network_cleanup_verified=True,
        )

    def abort(self, *, agent_container_name: str | None = None) -> None:
        """Remove a partial topology; raise if absence cannot be proved."""
        if self._finished:
            return
        failure = self._cleanup(agent_container_name=agent_container_name)
        self._finished = True
        if failure is not None:
            raise CredentialBrokerContainmentError(
                "partial credential broker cleanup could not be mechanically verified"
            ) from failure

    def _verify_static_identity(self) -> None:
        policy = compiled_credential_isolation_policy()
        observed_source = broker_source_inventory_sha256(self._repository)
        if observed_source != policy.broker_source_inventory_sha256:
            raise CredentialBrokerError(
                "credential-broker source differs from the signed Protocol 2 inventory"
            )
        image_id, repo_digests = inspect_docker_image(
            self._broker.image,
            runtime=self._runtime,
        )
        if not _image_identity_matches(self._broker.image_digest, image_id, repo_digests):
            raise CredentialBrokerError("credential-broker image differs from its declared digest")
        if not verification_image_id_is_approved(compiled_verification_image_policy(), image_id):
            raise CredentialBrokerError("credential-broker image is not protocol-approved")
        self._source_inventory_sha256 = observed_source
        self._broker_image_id = image_id
        self._broker_repo_digests = repo_digests
        self._broker_image_environment = self._inspect_image_environment(image_id)
        self._identity_hashes = credential_identity_payloads(
            route=self._route,
            broker=self._broker,
            api_key_env=self._route.agent_credential_environment_name,
            source_inventory_sha256=observed_source,
        )
        if self._config.container_image is None or self._config.container_image_digest is None:
            raise CredentialBrokerError("credential-isolated agent image pin is missing")
        agent_image_id, agent_repo_digests = inspect_docker_image(
            self._config.container_image,
            runtime=self._runtime,
        )
        if not _image_identity_matches(
            self._config.container_image_digest,
            agent_image_id,
            agent_repo_digests,
        ):
            raise CredentialBrokerError("agent image differs from its declared digest")
        self._agent_image_id = agent_image_id
        self._image_environment = self._inspect_image_environment(agent_image_id)
        self._reject_baked_credential_environment(self._image_environment)
        self._reject_agent_image_volumes(agent_image_id)
        metadata_scan_sha256 = self._scan_agent_image_metadata(agent_image_id)
        rootfs_scan_sha256 = self._scan_agent_image_rootfs(agent_image_id)
        self._agent_image_credential_scan_sha256 = sha256_bytes(
            canonical_json_bytes(
                {
                    "image_runtime_metadata_sha256": metadata_scan_sha256,
                    "rootfs_inventory_sha256": rootfs_scan_sha256,
                }
            )
        )

    def _prepare_evidence_files(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="stinger-credential-broker-")
        root = Path(temporary.name)
        root.chmod(0o700)
        config_dir = root / "config"
        audit_dir = root / "audit"
        config_dir.mkdir(mode=0o700)
        audit_dir.mkdir(mode=0o700)
        config_path = config_dir / "config.json"
        audit_path = audit_dir / "audit.jsonl"
        configuration_sha256 = self._require_identity_hashes()[1]
        payload = {
            "format_version": "1",
            "configuration_sha256": configuration_sha256,
            "provider": self._route.provider.value,
            "agent_base_url": self._route.agent_base_url,
            "upstream_https_origin": self._route.upstream_https_origin,
            "path_mappings": [item.model_dump(mode="json") for item in self._route.path_mappings],
            "forwarded_agent_headers": list(self._route.forwarded_agent_headers),
            "stripped_agent_headers": list(self._route.stripped_agent_headers),
            "injected_auth_header": self._route.injected_auth_header,
            "injected_auth_scheme": self._route.injected_auth_scheme,
            "lease_sha256": sha256_bytes(self._lease.encode("utf-8")),
            "test_only_allow_http": False,
        }
        encoded = canonical_json_bytes(payload)
        config_path.write_bytes(encoded)
        config_path.chmod(0o400)
        self._temporary = temporary
        self._temporary_path = root
        self._config_path = config_path
        self._audit_path = audit_path
        self._configuration_bytes = encoded

    def _create_internal_network(self) -> None:
        self._network_creation_attempted = True
        result = run_docker(
            (
                "network",
                "create",
                "--driver",
                "bridge",
                "--internal",
                "--ipv6=false",
                "--opt",
                "com.docker.network.bridge.gateway_mode_ipv4=isolated",
                "--opt",
                "com.docker.network.enable_ipv4=true",
                "--label",
                "stinger.credential-isolation=protocol-2",
                self.network_name,
            ),
            runtime=self._runtime,
            observe_if_missing=False,
        )
        network_id = result.stdout.strip()
        if result.returncode != 0 or _CONTAINER_ID.fullmatch(network_id) is None:
            raise CredentialBrokerError("fresh Docker-internal network could not be created")
        self._network_id = network_id
        network = self._inspect_network()
        if (
            network.get("Name") != self.network_name
            or network.get("Id") != network_id
            or network.get("Driver") != "bridge"
            or network.get("EnableIPv4") is not True
            or network.get("EnableIPv6") is not False
            or network.get("Internal") is not True
            or network.get("Attachable") is not False
            or network.get("Ingress") is True
            or network.get("Options")
            != {
                "com.docker.network.bridge.gateway_mode_ipv4": "isolated",
                "com.docker.network.enable_ipv4": "true",
            }
            or not _network_ipam_is_isolated(network.get("IPAM"))
            or network.get("Containers") not in ({}, None)
        ):
            raise CredentialBrokerError("fresh agent network does not match the closed topology")

    def _start_broker_container(self) -> None:
        config_path = self._require_config_path()
        audit_dir = self._require_audit_path().parent
        source = (self._repository / BROKER_SERVER_SOURCE).resolve(strict=True)
        source_environment = {
            BROKER_RAW_CREDENTIAL_ENV: self._raw_credential,
            BROKER_LEASE_ENV: self._lease,
        }
        arguments: list[str] = [
            "run",
            "--detach",
            "--name",
            self.broker_container_name,
            "--network",
            "bridge",
            "--workdir",
            "/",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--no-healthcheck",
            "--sysctl",
            "net.ipv4.conf.all.forwarding=0",
            "--sysctl",
            "net.ipv6.conf.all.forwarding=0",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
            "--volume",
            f"{source}:{BROKER_SERVER_PATH}:ro",
            "--volume",
            f"{config_path}:{BROKER_CONFIG_PATH}:ro",
            "--volume",
            f"{audit_dir}:/evidence:rw",
            "--env",
            BROKER_RAW_CREDENTIAL_ENV,
            "--env",
            BROKER_LEASE_ENV,
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--env",
            "PYTHONHASHSEED=0",
            "--entrypoint",
            "python",
        ]
        if hasattr(os, "getuid"):
            arguments.extend(("--user", f"{os.getuid()}:{os.getgid()}"))
        arguments.extend(
            (
                self._require_broker_image_id(),
                "-B",
                BROKER_SERVER_PATH,
                BROKER_CONFIG_PATH,
                BROKER_AUDIT_PATH,
            )
        )
        result = run_docker(
            arguments,
            runtime=self._runtime,
            source_environment=source_environment,
            forwarded_names=(BROKER_RAW_CREDENTIAL_ENV, BROKER_LEASE_ENV),
            observe_if_missing=False,
        )
        container_id = result.stdout.strip()
        if result.returncode != 0 or _CONTAINER_ID.fullmatch(container_id) is None:
            raise CredentialBrokerError("credential-broker container could not be started")
        self._broker_container_id = container_id

    def _connect_and_verify_broker(self) -> None:
        result = run_docker(
            (
                "network",
                "connect",
                "--alias",
                BROKER_ALIAS,
                self.network_name,
                self.broker_container_name,
            ),
            runtime=self._runtime,
            observe_if_missing=False,
        )
        if result.returncode != 0:
            raise CredentialBrokerError("credential broker could not join the internal network")
        self._verify_broker_runtime_state()

    def _wait_until_ready(self) -> None:
        audit = self._require_audit_path()
        deadline = time.monotonic() + _READY_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if audit.is_file() and audit.stat().st_size:
                encoded = audit.read_bytes()
                first = encoded.splitlines(keepends=True)[0]
                try:
                    event = json.loads(first)
                except json.JSONDecodeError as exc:
                    raise CredentialBrokerError("broker readiness evidence is invalid") from exc
                if first != canonical_json_bytes(event):
                    raise CredentialBrokerError("broker readiness evidence is not canonical")
                if event != {
                    "configuration_sha256": self._require_identity_hashes()[1],
                    "decision": "ready",
                    "listen": "0.0.0.0:8765",
                    "provider": self._route.provider.value,
                }:
                    raise CredentialBrokerError("broker readiness identity does not match")
                return
            state = self._inspect_container_state(self.broker_container_name)
            if state.get("Running") is not True:
                raise CredentialBrokerError("credential broker exited before readiness")
            time.sleep(0.05)
        raise CredentialBrokerError("credential broker readiness timed out")

    def _inspect_agent_container(
        self,
        *,
        agent_container_name: str,
        agent_image: str,
        workdir: Path,
        exit_code: int,
        expected_command: tuple[str, ...],
    ) -> dict[str, Any]:
        record = self._inspect_container(agent_container_name)
        container_id = record.get("Id")
        if not isinstance(container_id, str) or _CONTAINER_ID.fullmatch(container_id) is None:
            raise CredentialBrokerError("agent container identity is invalid")
        state = record.get("State")
        config = record.get("Config")
        host = record.get("HostConfig")
        mounts = record.get("Mounts")
        networks = (record.get("NetworkSettings") or {}).get("Networks")
        if not all(isinstance(value, dict) for value in (state, config, host, networks)):
            raise CredentialBrokerError("agent container evidence schema is invalid")
        assert isinstance(state, dict)
        assert isinstance(config, dict)
        assert isinstance(host, dict)
        assert isinstance(networks, dict)
        if not self._agent_image_metadata_scanned:
            raise CredentialBrokerError("agent image runtime metadata was not scanned")
        expected_entrypoint = (
            list(self._agent_image_entrypoint) if self._agent_image_entrypoint else None
        )
        expected_user = _container_user()
        security_options = host.get("SecurityOpt")
        if (
            state.get("Running") is not False
            or state.get("ExitCode") != exit_code
            or record.get("Image") != agent_image
            or config.get("Image") != agent_image
            or config.get("Entrypoint") != expected_entrypoint
            or config.get("Cmd") != list(expected_command)
            or config.get("Healthcheck") != {"Test": ["NONE"]}
            or config.get("User") != expected_user
            or config.get("WorkingDir") != "/work"
            or state.get("Health") not in (None, {})
            or host.get("NetworkMode") != self.network_name
            or host.get("Privileged") is not False
            or host.get("AutoRemove") is not False
            or host.get("CapAdd") not in (None, [])
            or host.get("CapDrop") != ["ALL"]
            or host.get("PidMode") != ""
            or host.get("UsernsMode") != ""
            or host.get("ExtraHosts") not in (None, [])
            or host.get("Links") not in (None, [])
            or host.get("PublishAllPorts") is not False
            or host.get("PortBindings") not in (None, {})
            or host.get("Dns") != ["127.0.0.1"]
            or host.get("DnsSearch") != ["."]
            or host.get("DnsOptions") != ["timeout:1", "attempts:1"]
            or not _security_options_are_exact(security_options)
            or host.get("Sysctls")
            != {
                "net.ipv4.conf.all.forwarding": "0",
                "net.ipv6.conf.all.forwarding": "0",
            }
            or set(networks) != {self.network_name}
        ):
            raise CredentialBrokerError("agent container runtime identity drifted")
        internal_attachment = networks[self.network_name]
        if (
            not isinstance(internal_attachment, dict)
            or internal_attachment.get("Gateway") not in {"", None}
            or internal_attachment.get("IPv6Gateway") not in {"", None}
            or internal_attachment.get("GlobalIPv6Address") not in {"", None}
        ):
            raise CredentialBrokerError("agent network exposes an unapproved gateway")
        if not expected_command or any(
            self._raw_credential in argument for argument in expected_command
        ):
            raise CredentialBrokerError("agent command projection is invalid")
        environment = _environment_mapping(config.get("Env"))
        expected_environment = dict(self._require_image_environment())
        expected_environment.update(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0",
                "HOME": "/tmp",
                **self.agent_environment(),
            }
        )
        if environment != expected_environment:
            raise CredentialBrokerError("agent environment contains an extra or drifted value")
        if any(self._raw_credential in value for value in environment.values()):
            raise CredentialBrokerError("raw provider credential entered the agent environment")
        self._reject_extra_runtime_credentials(environment)
        mount_inventory = self._validate_agent_mounts(mounts, workdir)
        environment_inventory = {
            "entries": [
                {"name": name, "value_sha256": sha256_bytes(value.encode("utf-8"))}
                for name, value in sorted(environment.items())
            ]
        }
        attachment_inventory = {
            "agent_container_id_sha256": sha256_bytes(container_id.encode("ascii")),
            "agent_networks": [self.network_name],
            "broker_alias": BROKER_ALIAS,
            "broker_networks": ["bridge", self.network_name],
            "internal_network": True,
            "bridge_gateway_mode_ipv4": "isolated",
            "container_dns_upstream": "loopback-only",
            "host_gateway_present": False,
            "internal_network_id_sha256": sha256_bytes(self._require_network_id().encode("ascii")),
            "ipv6_enabled": False,
            "linux_capabilities": [],
            "no_new_privileges": True,
            "packet_forwarding": False,
        }
        runtime_identity_inventory = {
            "auto_remove": False,
            "capabilities_added": [],
            "capabilities_dropped": ["ALL"],
            "extra_hosts": [],
            "healthcheck_disabled": True,
            "links": [],
            "no_new_privileges": True,
            "pid_mode": "private-container",
            "port_bindings": [],
            "privileged": False,
            "publish_all_ports": False,
            "runtime_user": expected_user,
            "user_namespace_mode": "daemon-default",
            "working_directory": "/work",
        }
        return {
            "agent_container_id": container_id,
            "command_inventory": {
                "argument_count": len(expected_command),
                "argv_sha256": sha256_bytes(canonical_json_bytes(list(expected_command))),
            },
            "environment_inventory": environment_inventory,
            "mount_inventory": mount_inventory,
            "network_attachment_inventory": attachment_inventory,
            "runtime_identity_inventory": runtime_identity_inventory,
        }

    def _verify_broker_runtime_state(self) -> dict[str, Any]:
        record = self._inspect_container(self.broker_container_name)
        container_id = record.get("Id")
        image_id = record.get("Image")
        config = record.get("Config")
        state = record.get("State")
        host = record.get("HostConfig")
        network_settings = record.get("NetworkSettings")
        mounts = record.get("Mounts")
        if not all(isinstance(value, dict) for value in (config, state, host, network_settings)):
            raise CredentialBrokerError("credential-broker container evidence is invalid")
        assert isinstance(config, dict)
        assert isinstance(state, dict)
        assert isinstance(host, dict)
        assert isinstance(network_settings, dict)
        networks = network_settings.get("Networks")
        security_options = host.get("SecurityOpt")
        expected_user = _container_user()
        expected_environment = dict(self._require_broker_image_environment())
        expected_environment.update(
            {
                BROKER_RAW_CREDENTIAL_ENV: self._raw_credential,
                BROKER_LEASE_ENV: self._lease,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0",
            }
        )
        if (
            container_id != self._require_broker_container_id()
            or image_id != self._require_broker_image_id()
            or config.get("Image") != self._require_broker_image_id()
            or state.get("Running") is not True
            or state.get("Health") not in (None, {})
            or host.get("NetworkMode") != "bridge"
            or not isinstance(networks, dict)
            or set(networks) != {"bridge", self.network_name}
            or host.get("CapDrop") != ["ALL"]
            or host.get("CapAdd") not in (None, [])
            or host.get("AutoRemove") is not False
            or host.get("PidMode") != ""
            or host.get("UsernsMode") != ""
            or host.get("ExtraHosts") not in (None, [])
            or host.get("Links") not in (None, [])
            or not _security_options_are_exact(security_options)
            or host.get("Sysctls")
            != {
                "net.ipv4.conf.all.forwarding": "0",
                "net.ipv6.conf.all.forwarding": "0",
            }
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or host.get("PublishAllPorts") is not False
            or host.get("PortBindings") not in (None, {})
            or config.get("ExposedPorts") not in (None, {})
            or network_settings.get("Ports") not in (None, {})
            or config.get("User") != expected_user
            or config.get("WorkingDir") != "/"
            or config.get("Entrypoint") != ["python"]
            or config.get("Healthcheck") != {"Test": ["NONE"]}
            or config.get("Cmd")
            != ["-B", BROKER_SERVER_PATH, BROKER_CONFIG_PATH, BROKER_AUDIT_PATH]
            or _environment_mapping(config.get("Env")) != expected_environment
            or not _tmpfs_is_exact(host.get("Tmpfs"))
        ):
            raise CredentialBrokerError("credential-broker runtime identity drifted")
        internal = networks[self.network_name]
        aliases = internal.get("Aliases") if isinstance(internal, dict) else None
        if not isinstance(aliases, list) or BROKER_ALIAS not in aliases:
            raise CredentialBrokerError("credential-broker internal alias is missing")
        self._validate_broker_mounts(mounts)
        return {
            "auto_remove": False,
            "capabilities_added": [],
            "capabilities_dropped": ["ALL"],
            "entrypoint": ["python"],
            "extra_hosts": [],
            "healthcheck_disabled": True,
            "links": [],
            "network_modes": ["bridge", "fresh-docker-internal-network-only"],
            "no_new_privileges": True,
            "pid_mode": "private-container",
            "port_bindings": [],
            "privileged": False,
            "publish_all_ports": False,
            "read_only_rootfs": True,
            "runtime_user": expected_user,
            "user_namespace_mode": "daemon-default",
            "working_directory": "/",
        }

    def _verify_internal_network_membership(self) -> None:
        network = self._inspect_network()
        if (
            network.get("Id") != self._require_network_id()
            or network.get("Name") != self.network_name
            or network.get("Driver") != "bridge"
            or network.get("Internal") is not True
            or network.get("EnableIPv4") is not True
            or network.get("EnableIPv6") is not False
            or network.get("Options")
            != {
                "com.docker.network.bridge.gateway_mode_ipv4": "isolated",
                "com.docker.network.enable_ipv4": "true",
            }
            or not _network_ipam_is_isolated(network.get("IPAM"))
        ):
            raise CredentialBrokerError("agent internal network identity drifted")
        containers = network.get("Containers") or {}
        if not isinstance(containers, dict):
            raise CredentialBrokerError("agent internal network membership is invalid")
        names = {
            value.get("Name")
            for value in containers.values()
            if isinstance(value, dict) and isinstance(value.get("Name"), str)
        }
        # Docker removes stopped containers from `network inspect .Containers`. The stopped
        # agent's own inspect above proves its sole attachment; the live-network inventory
        # must therefore contain exactly the broker and no third container at this phase.
        if names != {self.broker_container_name}:
            raise CredentialBrokerError("agent network membership is not exact")

    def _quiesce_broker(self) -> None:
        """Gracefully stop the broker so its terminal audit is stable before reading it."""
        result = run_docker(
            ("container", "stop", "--time", "130", self.broker_container_name),
            runtime=self._runtime,
            timeout=140,
            observe_if_missing=False,
        )
        if result.returncode != 0 or result.stdout.strip() != self.broker_container_name:
            raise CredentialBrokerError("credential broker could not be quiesced")
        state = self._inspect_container_state(self.broker_container_name)
        if (
            state.get("Running") is not False
            or state.get("ExitCode") != 0
            or state.get("OOMKilled") is not False
            or state.get("Error") not in {"", None}
        ):
            raise CredentialBrokerError("credential broker did not quiesce cleanly")
        self._broker_quiesced = True

    def _load_and_verify_audit(self) -> tuple[bytes, tuple[int, int]]:
        path = self._require_audit_path()
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise CredentialBrokerError("broker audit evidence is missing") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise CredentialBrokerError("broker audit evidence is not a regular file")
        encoded = path.read_bytes()
        if not encoded or len(encoded) > _MAX_AUDIT_BYTES or not encoded.endswith(b"\n"):
            raise CredentialBrokerError("broker audit evidence is empty or unbounded")
        events: list[dict[str, Any]] = []
        for line in encoded.splitlines(keepends=True):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CredentialBrokerError("broker audit evidence is invalid") from exc
            if not isinstance(event, dict) or line != canonical_json_bytes(event):
                raise CredentialBrokerError("broker audit evidence is not canonical")
            events.append(event)
        if not self._broker_quiesced or len(events) < 4:
            raise CredentialBrokerError("broker audit was read before a terminal quiescence")
        configuration_sha256 = self._require_identity_hashes()[1]
        if events[0] != {
            "configuration_sha256": configuration_sha256,
            "decision": "ready",
            "listen": "0.0.0.0:8765",
            "provider": self._route.provider.value,
        }:
            raise CredentialBrokerError("broker audit readiness identity changed")
        terminal = events[-1]
        request_events = events[1:-1]
        if terminal != {
            "configuration_sha256": configuration_sha256,
            "decision": "quiesced",
            "provider": self._route.provider.value,
            "request_count": len({event.get("request_id") for event in request_events}),
        }:
            raise CredentialBrokerError("broker audit terminal identity changed")
        allowed_path_hashes = {
            sha256_bytes(item.agent_path.encode("utf-8")) for item in self._route.path_mappings
        }
        decisions: dict[int, list[str]] = {}
        for event in request_events:
            if set(event) != {
                "configuration_sha256",
                "decision",
                "method",
                "path_sha256",
                "reason",
                "request_id",
                "upstream_https_origin",
            }:
                raise CredentialBrokerError("broker audit request schema is not exact")
            request_id = event["request_id"]
            if (
                event["configuration_sha256"] != configuration_sha256
                or event["upstream_https_origin"] != self._route.upstream_https_origin
                or event["method"] != "POST"
                or event["path_sha256"] not in allowed_path_hashes
                or event["decision"]
                not in {"attempt", "allowed", "rejected", "upstream-error", "broker-error"}
                or not isinstance(request_id, int)
                or isinstance(request_id, bool)
                or request_id < 1
            ):
                raise CredentialBrokerError("broker audit request identity is not approved")
            decisions.setdefault(request_id, []).append(str(event["decision"]))
        if set(decisions) != set(range(1, len(decisions) + 1)) or any(
            values != ["attempt", "allowed"] for values in decisions.values()
        ):
            raise CredentialBrokerError("broker did not record only approved provider requests")
        return encoded, (len(decisions), 0)

    def _verify_static_bytes_unchanged(self) -> None:
        config_path = self._require_config_path()
        if config_path.read_bytes() != self._require_configuration_bytes():
            raise CredentialBrokerError("credential-broker configuration changed during execution")
        if broker_source_inventory_sha256(self._repository) != self._require_source_inventory():
            raise CredentialBrokerError("credential-broker source changed during execution")
        image_id, repo_digests = inspect_docker_image(
            self._require_broker_image_id(),
            runtime=self._runtime,
        )
        if image_id != self._require_broker_image_id() or repo_digests != self._broker_repo_digests:
            raise CredentialBrokerError("credential-broker image identity changed during execution")
        verify_docker_runtime(self._runtime)

    def _reject_raw_credential_artifacts(
        self,
        transcript: str,
        workdir: Path,
        audit: bytes,
    ) -> None:
        variants = _credential_variants(self._raw_credential.encode("utf-8"))
        if (
            _contains_credential_variant(transcript.encode("utf-8"), variants)
            or _contains_credential_variant(audit, variants)
            or _contains_credential_variant(self._require_configuration_bytes(), variants)
        ):
            raise CredentialBrokerError(
                "provider credential or a reversible encoding appeared in agent evidence"
            )
        self._reject_credential_in_workdir(workdir, variants)

    def _reject_credential_in_workdir(
        self,
        workdir: Path,
        variants: tuple[bytes, ...],
    ) -> None:
        try:
            root = workdir.resolve(strict=True)
        except OSError as exc:
            raise CredentialBrokerError(
                "agent workdir could not be resolved for credential scanning"
            ) from exc
        for path in sorted(root.rglob("*")):
            relative = str(path.relative_to(root)).encode("utf-8", errors="surrogateescape")
            if _contains_credential_variant(relative, variants):
                raise CredentialBrokerError(
                    "provider credential or a reversible encoding appeared in a workdir path"
                )
            if path.is_symlink():
                try:
                    target = os.readlink(path).encode("utf-8", errors="surrogateescape")
                except OSError as exc:
                    raise CredentialBrokerError(
                        "agent workdir link could not be scanned for credential exposure"
                    ) from exc
                if _contains_credential_variant(target, variants):
                    raise CredentialBrokerError(
                        "provider credential or a reversible encoding appeared in a workdir link"
                    )
                continue
            if not path.is_file():
                continue
            try:
                with path.open("rb") as stream:
                    if _stream_contains_credential_variant(stream, variants):
                        raise CredentialBrokerError(
                            "provider credential or a reversible encoding appeared in the "
                            "agent workdir"
                        )
            except OSError as exc:
                raise CredentialBrokerError(
                    "agent workdir could not be scanned for credential exposure"
                ) from exc

    def _inspect_container(self, name: str) -> dict[str, Any]:
        result = run_docker(
            ("container", "inspect", name),
            runtime=self._runtime,
            observe_if_missing=False,
        )
        if result.returncode != 0:
            raise CredentialBrokerError("agent container could not be inspected before cleanup")
        try:
            raw = json.loads(result.stdout)
            record = raw[0]
        except (json.JSONDecodeError, IndexError, TypeError):
            raise CredentialBrokerError("agent container inspection is invalid") from None
        if not isinstance(record, dict):
            raise CredentialBrokerError("agent container inspection is invalid")
        return record

    def _inspect_container_state(self, name: str) -> dict[str, Any]:
        result = run_docker(
            ("container", "inspect", "--format", "{{json .State}}", name),
            runtime=self._runtime,
            observe_if_missing=False,
        )
        if result.returncode != 0:
            raise CredentialBrokerError("container state is unavailable")
        try:
            state = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise CredentialBrokerError("container state is invalid") from exc
        if not isinstance(state, dict):
            raise CredentialBrokerError("container state is invalid")
        return state

    def _inspect_network(self) -> dict[str, Any]:
        result = run_docker(
            ("network", "inspect", self.network_name),
            runtime=self._runtime,
            observe_if_missing=False,
        )
        if result.returncode != 0:
            raise CredentialBrokerError("agent internal network is unavailable")
        try:
            raw = json.loads(result.stdout)
            network = raw[0]
        except (json.JSONDecodeError, IndexError, TypeError):
            raise CredentialBrokerError("agent internal network evidence is invalid") from None
        if not isinstance(network, dict):
            raise CredentialBrokerError("agent internal network evidence is invalid")
        return network

    def _inspect_image_environment(self, image: str) -> dict[str, str]:
        result = run_docker(
            ("image", "inspect", "--format", "{{json .Config.Env}}", image),
            runtime=self._runtime,
            observe_if_missing=False,
        )
        if result.returncode != 0:
            raise CredentialBrokerError("agent image environment is unavailable")
        try:
            raw = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise CredentialBrokerError("agent image environment is invalid") from exc
        return _environment_mapping(raw)

    def _scan_agent_image_metadata(self, image: str) -> str:
        result = run_docker(
            ("image", "inspect", image),
            runtime=self._runtime,
            observe_if_missing=False,
        )
        if result.returncode != 0:
            raise CredentialBrokerError("agent image runtime metadata is unavailable")
        try:
            records = json.loads(result.stdout)
            record = records[0]
            config = record["Config"]
        except (json.JSONDecodeError, IndexError, KeyError, TypeError):
            raise CredentialBrokerError("agent image runtime metadata is invalid") from None
        if not isinstance(config, dict):
            raise CredentialBrokerError("agent image runtime metadata is invalid")
        encoded = canonical_json_bytes(config)
        variants = _credential_variants(self._raw_credential.encode("utf-8"))
        if _contains_credential_variant(encoded, variants):
            raise CredentialBrokerError(
                "provider credential or a reversible encoding is readable from agent image "
                "runtime metadata"
            )
        entrypoint = config.get("Entrypoint")
        command = config.get("Cmd")
        if entrypoint is not None and (
            not isinstance(entrypoint, list)
            or not entrypoint
            or any(not isinstance(value, str) for value in entrypoint)
        ):
            raise CredentialBrokerError("agent image entrypoint metadata is ambiguous")
        if command is not None and (
            not isinstance(command, list)
            or not command
            or any(not isinstance(value, str) for value in command)
        ):
            raise CredentialBrokerError("agent image command metadata is ambiguous")
        assert entrypoint is None or isinstance(entrypoint, list)
        self._agent_image_entrypoint = () if entrypoint is None else tuple(entrypoint)
        self._agent_image_metadata_scanned = True
        return sha256_bytes(encoded)

    def _reject_agent_image_volumes(self, image: str) -> None:
        result = run_docker(
            ("image", "inspect", "--format", "{{json .Config.Volumes}}", image),
            runtime=self._runtime,
            observe_if_missing=False,
        )
        if result.returncode != 0:
            raise CredentialBrokerError("agent image volume declarations are unavailable")
        try:
            volumes = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise CredentialBrokerError("agent image volume declarations are invalid") from exc
        if volumes not in (None, {}):
            raise CredentialBrokerError(
                "agent image declares volumes that evade final-rootfs credential scanning"
            )

    def _scan_agent_image_rootfs(self, image: str) -> str:
        raw_sha256 = sha256_bytes(self._raw_credential.encode("utf-8"))
        policy_sha256 = self._require_identity_hashes()[0]
        config_home_sha256 = sha256_bytes(canonical_json_bytes(self._agent_config_home_prefixes()))
        cache_key = (image, raw_sha256, policy_sha256, config_home_sha256)
        cached = _ROOTFS_SCAN_CACHE.get(cache_key)
        if cached is not None:
            return cached
        container_name = f"stinger-image-scan-{uuid4().hex[:12]}"
        scan_failure: BaseException | None = None
        inventory_sha256: str | None = None
        try:
            created = run_docker(
                (
                    "container",
                    "create",
                    "--name",
                    container_name,
                    "--network",
                    "none",
                    "--entrypoint",
                    "",
                    image,
                    "/bin/true",
                ),
                runtime=self._runtime,
                observe_if_missing=False,
            )
            if created.returncode != 0 or _CONTAINER_ID.fullmatch(created.stdout.strip()) is None:
                raise CredentialBrokerError(
                    "agent image final root filesystem could not be materialized"
                )
            with tempfile.TemporaryDirectory(prefix="stinger-agent-image-scan-") as temporary:
                archive_path = Path(temporary) / "rootfs.tar"
                exported = run_docker(
                    (
                        "container",
                        "export",
                        "--output",
                        str(archive_path),
                        container_name,
                    ),
                    runtime=self._runtime,
                    timeout=300,
                    observe_if_missing=False,
                )
                if exported.returncode != 0:
                    raise CredentialBrokerError(
                        "agent image final root filesystem could not be exported"
                    )
                inventory_sha256 = self._scan_rootfs_archive(archive_path)
        except BaseException as exc:
            scan_failure = exc
        try:
            terminate_docker_container(container_name, runtime=self._runtime, timeout=30)
        except DockerRuntimeError as exc:
            raise CredentialBrokerContainmentError(
                "agent image credential-scan container cleanup was not verified"
            ) from exc
        if scan_failure is not None:
            if isinstance(scan_failure, CredentialBrokerError):
                raise scan_failure
            if isinstance(scan_failure, Exception):
                raise CredentialBrokerError(
                    "agent image credential scan failed closed"
                ) from scan_failure
            raise scan_failure
        if inventory_sha256 is None:
            raise CredentialBrokerError("agent image credential scan produced no inventory")
        _ROOTFS_SCAN_CACHE[cache_key] = inventory_sha256
        return inventory_sha256

    def _scan_rootfs_archive(self, archive_path: Path) -> str:
        try:
            metadata = archive_path.lstat()
        except OSError as exc:
            raise CredentialBrokerError("agent image rootfs archive is missing") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise CredentialBrokerError("agent image rootfs archive is not a regular file")
        variants = _credential_variants(self._raw_credential.encode("utf-8"))
        overlap_size = max(len(value) for value in variants) - 1
        config_home_prefixes = self._agent_config_home_prefixes()
        try:
            with archive_path.open("rb") as encoded_archive:
                if _stream_contains_credential_variant(encoded_archive, variants):
                    raise CredentialBrokerError(
                        "provider credential or a reversible encoding is readable from the "
                        "agent image archive"
                    )
        except OSError as exc:
            raise CredentialBrokerError("agent image rootfs archive is unreadable") from exc
        entries: list[dict[str, object]] = []
        seen: set[str] = set()
        with tarfile.open(archive_path, mode="r|*") as archive:
            for member in archive:
                path = _canonical_archive_path(member.name)
                if path in seen:
                    raise CredentialBrokerError("agent image rootfs archive has duplicate paths")
                seen.add(path)
                config_home_match = next(
                    (
                        prefix
                        for prefix in config_home_prefixes
                        if path == prefix or path.startswith(f"{prefix}/")
                    ),
                    None,
                )
                if _is_known_credential_path(path) or (
                    config_home_match is not None
                    and (path != config_home_match or not member.isdir())
                ):
                    raise CredentialBrokerError(
                        "agent image contains a prohibited credential-file path"
                    )
                entry: dict[str, object] = {
                    "mode": member.mode,
                    "path": path,
                    "size": member.size,
                    "type": member.type.decode("ascii", errors="strict"),
                }
                if member.isfile():
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise CredentialBrokerError("agent image regular file is unreadable")
                    digest = hashlib.sha256()
                    overlap = b""
                    while chunk := stream.read(1024 * 1024):
                        digest.update(chunk)
                        combined = overlap + chunk
                        if _contains_credential_variant(combined, variants):
                            raise CredentialBrokerError(
                                "raw provider credential is readable from the agent image"
                            )
                        overlap = combined[-overlap_size:]
                    entry["sha256"] = digest.hexdigest()
                elif member.issym() or member.islnk():
                    target = member.linkname.encode("utf-8", errors="surrogateescape")
                    if _contains_credential_variant(target, variants):
                        raise CredentialBrokerError(
                            "raw provider credential is readable from an agent image link"
                        )
                    entry["target_sha256"] = sha256_bytes(target)
                entries.append(entry)
        entries.sort(key=lambda item: str(item["path"]))
        return sha256_bytes(canonical_json_bytes({"entries": entries}))

    def _agent_config_home_prefixes(self) -> tuple[str, ...]:
        environment = self._require_image_environment()
        if self._route.agent_adapter == "codex":
            raw_paths = (environment.get("CODEX_HOME", "/tmp/.codex"),)
        else:
            raw_paths = (environment.get("CLAUDE_CONFIG_DIR", "/tmp/.claude"),)
        prefixes: list[str] = []
        for value in raw_paths:
            parts = value.removeprefix("/").split("/")
            if (
                not value.startswith("/")
                or value == "/"
                or value.endswith("/")
                or "\x00" in value
                or any(part in {"", ".", ".."} for part in parts)
            ):
                raise CredentialBrokerError("agent image config home is not canonical")
            prefixes.append("/".join(parts))
        return tuple(sorted(prefixes))

    def _reject_baked_credential_environment(self, environment: Mapping[str, str]) -> None:
        for name, value in environment.items():
            if value and _is_sensitive_environment_value(name, value):
                raise CredentialBrokerError(
                    "agent image contains an extra credential or routing environment value"
                )

    def _reject_extra_runtime_credentials(self, environment: Mapping[str, str]) -> None:
        allowed = set(agent_environment_names(self._route))
        for name, value in environment.items():
            if value and name not in allowed and _is_sensitive_environment_value(name, value):
                raise CredentialBrokerError(
                    "agent container contains an extra credential or routing environment value"
                )

    def _validate_agent_mounts(self, mounts: object, workdir: Path) -> dict[str, Any]:
        if not isinstance(mounts, list) or len(mounts) != 1 or not isinstance(mounts[0], dict):
            raise CredentialBrokerError("agent container has an extra or missing mount")
        mount = mounts[0]
        if (
            mount.get("Type") != "bind"
            or mount.get("Source") != str(workdir.resolve())
            or mount.get("Destination") != "/work"
            or mount.get("RW") is not True
        ):
            raise CredentialBrokerError("agent workdir mount identity drifted")
        return {
            "mounts": [
                {
                    "destination": "/work",
                    "read_only": False,
                    "source_sha256": sha256_bytes(str(workdir.resolve()).encode("utf-8")),
                    "type": "bind",
                }
            ]
        }

    def _validate_broker_mounts(self, mounts: object) -> None:
        if not isinstance(mounts, list) or len(mounts) != 3:
            raise CredentialBrokerError("credential broker mount inventory is not exact")
        actual = {
            (
                item.get("Destination"),
                item.get("RW"),
                item.get("Source"),
                item.get("Type"),
            )
            for item in mounts
            if isinstance(item, dict)
        }
        source = str((self._repository / BROKER_SERVER_SOURCE).resolve(strict=True))
        expected = {
            (BROKER_SERVER_PATH, False, source, "bind"),
            (BROKER_CONFIG_PATH, False, str(self._require_config_path()), "bind"),
            ("/evidence", True, str(self._require_audit_path().parent), "bind"),
        }
        if actual != expected:
            raise CredentialBrokerError("credential broker mount inventory drifted")

    def _cleanup_after_failure(self, cause: BaseException) -> None:
        failure = self._cleanup(agent_container_name=None)
        self._finished = True
        if failure is not None:
            raise CredentialBrokerContainmentError(
                "credential broker setup failed and cleanup could not be verified"
            ) from failure

    def _cleanup(self, *, agent_container_name: str | None) -> BaseException | None:
        failure: BaseException | None = None
        for name in (agent_container_name, self.broker_container_name):
            if name is None:
                continue
            try:
                terminate_docker_container(name, runtime=self._runtime, timeout=30)
            except BaseException as exc:
                failure = failure or exc
        if self._network_creation_attempted:
            try:
                self._remove_network()
            except BaseException as exc:
                failure = failure or exc
        try:
            verify_docker_runtime(self._runtime)
        except BaseException as exc:
            failure = failure or exc
        if self._temporary is not None:
            try:
                self._temporary.cleanup()
            except BaseException as exc:
                failure = failure or exc
        return failure

    def _remove_network(self) -> None:
        run_docker(
            ("network", "rm", self.network_name),
            runtime=self._runtime,
            observe_if_missing=False,
        )
        observations = 0
        attempts = 0
        while attempts < 4 and observations < _NETWORK_ABSENCE_OBSERVATIONS:
            attempts += 1
            result = run_docker(
                ("network", "ls", "--format", "{{.Name}}"),
                runtime=self._runtime,
                observe_if_missing=False,
            )
            if result.returncode != 0:
                raise CredentialBrokerError("Docker network cleanup inventory failed")
            names = {line.strip() for line in result.stdout.splitlines() if line.strip()}
            if self.network_name in names:
                observations = 0
            else:
                observations += 1
            if observations < _NETWORK_ABSENCE_OBSERVATIONS:
                time.sleep(0.05)
        if observations < _NETWORK_ABSENCE_OBSERVATIONS:
            raise CredentialBrokerError("agent internal network cleanup was not verified")

    def _require_identity_hashes(self) -> tuple[str, str, str, str]:
        if self._identity_hashes is None:
            raise CredentialBrokerError("credential broker static identity is incomplete")
        return self._identity_hashes

    def _require_source_inventory(self) -> str:
        if self._source_inventory_sha256 is None:
            raise CredentialBrokerError("credential broker source identity is incomplete")
        return self._source_inventory_sha256

    def _require_broker_image_id(self) -> str:
        if self._broker_image_id is None:
            raise CredentialBrokerError("credential broker image identity is incomplete")
        return self._broker_image_id

    def _require_broker_container_id(self) -> str:
        if self._broker_container_id is None:
            raise CredentialBrokerError("credential broker container identity is incomplete")
        return self._broker_container_id

    def _require_network_id(self) -> str:
        if self._network_id is None:
            raise CredentialBrokerError("credential broker network identity is incomplete")
        return self._network_id

    def _require_temporary_path(self) -> Path:
        if self._temporary_path is None:
            raise CredentialBrokerError("credential broker evidence directory is incomplete")
        return self._temporary_path

    def _require_config_path(self) -> Path:
        if self._config_path is None:
            raise CredentialBrokerError("credential broker configuration path is incomplete")
        return self._config_path

    def _require_audit_path(self) -> Path:
        if self._audit_path is None:
            raise CredentialBrokerError("credential broker audit path is incomplete")
        return self._audit_path

    def _require_configuration_bytes(self) -> bytes:
        if self._configuration_bytes is None:
            raise CredentialBrokerError("credential broker configuration bytes are incomplete")
        return self._configuration_bytes

    def _require_image_environment(self) -> dict[str, str]:
        if self._image_environment is None:
            raise CredentialBrokerError("agent image environment identity is incomplete")
        return self._image_environment

    def _require_broker_image_environment(self) -> dict[str, str]:
        if self._broker_image_environment is None:
            raise CredentialBrokerError("broker image environment identity is incomplete")
        return self._broker_image_environment

    def _require_agent_image_credential_scan_sha256(self) -> str:
        if self._agent_image_credential_scan_sha256 is None:
            raise CredentialBrokerError("agent image credential scan identity is incomplete")
        return self._agent_image_credential_scan_sha256


def _environment_mapping(raw: object) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, list) or any(not isinstance(value, str) for value in raw):
        raise CredentialBrokerError("container environment inventory is invalid")
    environment: dict[str, str] = {}
    for entry in raw:
        name, separator, value = entry.partition("=")
        if not separator or not name or name in environment:
            raise CredentialBrokerError("container environment inventory is ambiguous")
        environment[name] = value
    return environment


def _is_sensitive_environment_value(name: str, value: str) -> bool:
    # Official Python base images expose a public signing-key fingerprint as GPG_KEY. It is
    # not an authentication secret; every other nonempty key/token/password/routing name is
    # rejected rather than guessed safe.
    if name == "GPG_KEY" and re.fullmatch(r"[0-9A-Fa-f]{40,64}", value) is not None:
        return False
    return bool(
        _PROVIDER_SECRET_NAME.search(name) or _PROXY_NAME.search(name) or _ROUTING_NAME.search(name)
    )


def _tmpfs_is_exact(raw: object) -> bool:
    if not isinstance(raw, dict) or set(raw) != {"/tmp"}:
        return False
    value = raw["/tmp"]
    if not isinstance(value, str):
        return False
    options = value.split(",")
    return len(options) == 6 and set(options) == {
        "rw",
        "noexec",
        "nosuid",
        "nodev",
        "size=16m",
        "mode=1777",
    }


def _container_user() -> str:
    """Return the exact Docker user projection for this host."""
    if not hasattr(os, "getuid"):  # pragma: no cover - Windows has no uid/gid
        return ""
    return f"{os.getuid()}:{os.getgid()}"


def _security_options_are_exact(raw: object) -> bool:
    """Accept Docker's canonical spellings of one enabled NNP option."""
    return (
        isinstance(raw, list)
        and len(raw) == 1
        and raw[0]
        in {
            "no-new-privileges",
            "no-new-privileges:true",
        }
    )


def _network_ipam_is_isolated(raw: object) -> bool:
    if not isinstance(raw, dict):
        return False
    configurations = raw.get("Config")
    if (
        raw.get("Driver") != "default"
        or raw.get("Options") not in ({}, None)
        or not isinstance(configurations, list)
        or len(configurations) != 1
        or not isinstance(configurations[0], dict)
        or set(configurations[0]) != {"Subnet"}
    ):
        return False
    subnet = configurations[0]["Subnet"]
    return isinstance(subnet, str) and bool(subnet)


def _credential_variants(raw: bytes) -> tuple[bytes, ...]:
    variants = {
        raw,
        raw.hex().encode("ascii"),
        raw.hex().upper().encode("ascii"),
        b64encode(raw),
        b64encode(raw).rstrip(b"="),
        urlsafe_b64encode(raw),
        urlsafe_b64encode(raw).rstrip(b"="),
        quote_from_bytes(raw).encode("ascii"),
        quote_from_bytes(raw).lower().encode("ascii"),
        quote_from_bytes(raw, safe="").encode("ascii"),
        quote_from_bytes(raw, safe="").lower().encode("ascii"),
    }
    return tuple(
        sorted((value for value in variants if value), key=lambda value: (len(value), value))
    )


def _contains_credential_variant(value: bytes, variants: tuple[bytes, ...]) -> bool:
    return any(candidate in value for candidate in variants)


def _stream_contains_credential_variant(
    stream: BinaryIO,
    variants: tuple[bytes, ...],
) -> bool:
    overlap_size = max(len(value) for value in variants) - 1
    overlap = b""
    while chunk := stream.read(1024 * 1024):
        combined = overlap + chunk
        if _contains_credential_variant(combined, variants):
            return True
        overlap = combined[-overlap_size:]
    return False


def _image_identity_matches(
    declared: str,
    image_id: str,
    repo_digests: tuple[str, ...],
) -> bool:
    return declared == image_id or any(value.endswith(f"@{declared}") for value in repo_digests)


def _canonical_archive_path(raw: str) -> str:
    path = raw.removeprefix("./")
    parts = path.split("/")
    if (
        not path
        or path.startswith("/")
        or "\x00" in path
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise CredentialBrokerError("agent image rootfs archive path is not canonical")
    return path


def _is_known_credential_path(path: str) -> bool:
    lowered = path.lower()
    parts = lowered.split("/")
    if parts[0] == "credentials":
        return True
    suffixes = (
        compiled_credential_isolation_policy().agent_image_prohibited_credential_path_suffixes
    )
    if any(f"/{lowered}".endswith(suffix) for suffix in suffixes):
        return True
    return "/.claude/" in lowered and any(
        token in parts[-1] for token in ("auth", "credential", "session", "token")
    )


def _required_text(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise CredentialBrokerError(f"credential-isolation evidence field {key!r} is missing")
    return value


__all__ = [
    "CredentialBrokerContainmentError",
    "CredentialBrokerError",
    "CredentialBrokerSession",
]
