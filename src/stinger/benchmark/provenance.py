"""Mechanical runtime provenance preflight for benchmark-capable runs."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

from stinger.adapters.base import AgentAdapter
from stinger.adapters.cli_base import AdapterSettingsError, CliAgentAdapter
from stinger.adapters.shell import ShellAdapterError
from stinger.benchmark.credential_broker import (
    BROKER_SERVER_SOURCE,
    broker_source_inventory_sha256,
    credential_identity_payloads,
    provider_route,
)
from stinger.benchmark.git_checkout import (
    DirtyGitCheckoutError,
    GitCheckoutError,
    VerifiedTrackedImplementation,
    verify_loaded_stinger_implementation,
)
from stinger.benchmark.protocol import (
    BenchmarkRuntimeProvenance,
    CredentialIsolationRuntimeProvenance,
    canonical_local_provider_binding_issues,
    compiled_credential_isolation_policy,
    publication_pin_issues,
)
from stinger.benchmark.verification_image import (
    VerificationImagePolicyError,
    compiled_verification_image_policy,
    verification_image_id_is_approved,
    verify_approved_verification_image,
)
from stinger.config import RunConfig
from stinger.docker_runtime import (
    DOCKER_RUNTIME_CLAIM_BOUNDARY,
    DockerRuntimeError,
    DockerRuntimeIdentity,
    docker_environment,
    inspect_docker_image,
    observe_docker_runtime,
    terminate_docker_container,
    verify_docker_runtime,
)
from stinger.harness.sandbox import Isolation, docker_argv

_PROBE_TIMEOUT_S = 30


class RuntimePreflightError(Exception):
    """Raised when local observations do not verify declared benchmark provenance."""

    def __init__(self, provenance: BenchmarkRuntimeProvenance) -> None:
        self.provenance = provenance
        super().__init__(
            "benchmark runtime provenance preflight failed: "
            + ", ".join(provenance.verification_issues)
        )


def verify_runtime_provenance(
    config: RunConfig,
    adapter: AgentAdapter,
    *,
    workdir: Path,
    repository: Path | None = None,
    docker_runtime_identity: DockerRuntimeIdentity | None = None,
    verification_image_identity: tuple[str, tuple[str, ...]] | None = None,
) -> BenchmarkRuntimeProvenance:
    """Observe and verify the exact local runtime before a benchmark run starts.

    Args:
        config: Fully resolved run configuration with benchmark mode enabled.
        adapter: Constructed agent adapter.
        workdir: Existing directory used for the non-network CLI version probe.
        repository: Stinger checkout whose exact HEAD is being run. Defaults to this module's
            repository root.
        docker_runtime_identity: Runtime already established by the verification sandbox.
        verification_image_identity: Immutable image ID and repository digests already
            established by that same sandbox.

    Returns:
        A verified provenance block safe to attach to the report.

    Raises:
        RuntimePreflightError: If any declaration is absent, unobservable, unsupported, or
            differs from the local executable/image/commit.
    """
    metadata = config.benchmark_metadata()
    if metadata is None:
        raise RuntimePreflightError(
            BenchmarkRuntimeProvenance(
                verification_issues=("benchmark_metadata_missing",),
            )
        )

    issues: list[str] = []
    checkout = repository or Path(__file__).resolve().parents[3]
    stinger_commit: str | None = None
    implementation: VerifiedTrackedImplementation | None = None
    expected_stinger_commit = metadata.stinger_commit
    if expected_stinger_commit is None:
        issues.append("stinger_commit_unobservable")
    else:
        try:
            implementation = verify_loaded_stinger_implementation(
                checkout,
                expected_commit=expected_stinger_commit,
                timeout=_PROBE_TIMEOUT_S,
            )
        except DirtyGitCheckoutError:
            issues.append("stinger_worktree_dirty")
        except GitCheckoutError:
            issues.append("stinger_loaded_implementation_unverified")
        else:
            stinger_commit = implementation.commit

    agent_image_id: str | None = None
    agent_repo_digests: tuple[str, ...] = ()
    verification_image_id: str | None = None
    verification_repo_digests: tuple[str, ...] = ()
    verification_image_policy_sha256: str | None = None
    docker_runtime: DockerRuntimeIdentity | None = None
    if config.isolation is Isolation.DOCKER or config.agent.container_image is not None:
        try:
            docker_runtime = (
                observe_docker_runtime()
                if docker_runtime_identity is None
                else verify_docker_runtime(docker_runtime_identity)
            )
        except DockerRuntimeError:
            issues.append("docker_runtime_unobservable")
    if config.isolation is not Isolation.DOCKER:
        issues.append("verification_image_not_containerized")
    else:
        try:
            if docker_runtime is None:
                raise VerificationImagePolicyError("Docker runtime is unavailable")
            approved_verifier = verify_approved_verification_image(
                repository=checkout,
                image=config.image,
                policy=compiled_verification_image_policy(),
                docker_runtime=docker_runtime,
            )
        except VerificationImagePolicyError:
            issues.append("verification_image_policy_unverified")
        else:
            docker_runtime = approved_verifier.docker_runtime
            verification_image_id = approved_verifier.image.image_id
            verification_repo_digests = approved_verifier.image.repo_digests
            verification_image_policy_sha256 = approved_verifier.policy_sha256
            if verification_image_identity is not None and verification_image_identity != (
                verification_image_id,
                verification_repo_digests,
            ):
                issues.append("verification_image_preflight_identity_mismatch")
    if "verification_image_policy_unverified" in issues:
        raise RuntimePreflightError(
            BenchmarkRuntimeProvenance(
                stinger_commit=stinger_commit,
                verification_image_id=verification_image_id,
                verification_image_repo_digests=verification_repo_digests,
                docker_client_sha256=(
                    None if docker_runtime is None else docker_runtime.client_sha256
                ),
                docker_runtime_fingerprint_sha256=(
                    None if docker_runtime is None else docker_runtime.fingerprint_sha256
                ),
                docker_runtime_claim_boundary=(
                    None if docker_runtime is None else DOCKER_RUNTIME_CLAIM_BOUNDARY
                ),
                verification_issues=tuple(dict.fromkeys(issues)),
            )
        )
    if config.agent.container_image is None:
        issues.append("agent_not_containerized")
    else:
        agent_image_id, agent_repo_digests = _docker_image_identity(
            config.agent.container_image,
            "agent_container_image_unobservable",
            issues,
            runtime=docker_runtime,
        )

    credential_isolation: CredentialIsolationRuntimeProvenance | None = None
    broker_image_id: str | None = None
    broker_repo_digests: tuple[str, ...] = ()
    broker = config.agent.credential_broker
    if broker is None:
        issues.append("credential_broker_configuration_missing")
    elif docker_runtime is None:
        issues.append("credential_broker_docker_runtime_unavailable")
    else:
        isolation_issues: list[str] = []
        policy = compiled_credential_isolation_policy()
        observed_broker_source_sha256: str | None = None
        try:
            observed_broker_source_sha256 = broker_source_inventory_sha256(checkout)
        except ValueError:
            isolation_issues.append("credential_broker_source_unobservable")
        else:
            if policy.broker_source_paths != (BROKER_SERVER_SOURCE,):
                isolation_issues.append("credential_broker_source_paths_unapproved")
            if observed_broker_source_sha256 != policy.broker_source_inventory_sha256:
                isolation_issues.append("credential_broker_source_not_protocol_approved")

        broker_image_id, broker_repo_digests = _docker_image_identity(
            broker.image,
            "credential_broker_image_unobservable",
            isolation_issues,
            runtime=docker_runtime,
        )
        if not _image_identity_matches(
            broker.image_digest,
            broker_image_id,
            broker_repo_digests,
        ):
            isolation_issues.append("credential_broker_image_identity_mismatch")
        if broker_image_id is None or not verification_image_id_is_approved(
            compiled_verification_image_policy(),
            broker_image_id,
        ):
            isolation_issues.append("credential_broker_image_not_protocol_approved")

        identities: tuple[str, str, str, str] | None = None
        if observed_broker_source_sha256 is not None and config.agent.api_key_env is not None:
            try:
                route = provider_route(config.agent.adapter, config.agent.provider)
                identities = credential_identity_payloads(
                    route=route,
                    broker=broker,
                    api_key_env=config.agent.api_key_env,
                    source_inventory_sha256=observed_broker_source_sha256,
                )
            except ValueError:
                isolation_issues.append("credential_broker_configuration_unresolved")
        else:
            isolation_issues.append("credential_broker_configuration_unresolved")
        if (
            identities is not None
            and broker_image_id is not None
            and observed_broker_source_sha256 is not None
        ):
            (
                policy_sha256,
                broker_configuration_sha256,
                allowed_destination_inventory_sha256,
                agent_projection_inventory_sha256,
            ) = identities
            credential_isolation = CredentialIsolationRuntimeProvenance(
                policy_sha256=policy_sha256,
                broker_configuration_sha256=broker_configuration_sha256,
                allowed_destination_inventory_sha256=(allowed_destination_inventory_sha256),
                agent_projection_inventory_sha256=agent_projection_inventory_sha256,
                broker_source_inventory_sha256=observed_broker_source_sha256,
                broker_image_id=broker_image_id,
                broker_image_repo_digests=broker_repo_digests,
                docker_runtime_fingerprint_sha256=docker_runtime.fingerprint_sha256,
                verified=not isolation_issues,
                verification_issues=tuple(dict.fromkeys(isolation_issues)),
            )
        issues.extend(isolation_issues)

    invocation: tuple[str, ...] = ()
    version_invocation: tuple[str, ...] = ()
    environment_names: tuple[str, ...] = ()
    observed_cli_version: str | None = None
    if not isinstance(adapter, CliAgentAdapter):
        issues.append("agent_adapter_runtime_unobservable")
    else:
        try:
            invocation = adapter.resolved_invocation_template()
            environment_names = adapter.resolved_environment_names()
            version_argv = adapter.version_argv()
            # Record the exact command *inside* the pinned agent image, not Docker's host
            # wrapper. The wrapper contains the operator's absolute workdir mount, which is
            # machine-private and irrelevant once the image digest and containerized
            # preflight are recorded.
            version_invocation = tuple(version_argv)
            if config.agent.container_image is None:
                observed_cli_version = _command_output(
                    version_argv,
                    cwd=workdir,
                    issue="agent_cli_version_unobservable",
                    issues=issues,
                )
            elif docker_runtime is None or agent_image_id is None:
                issues.append("agent_cli_version_unobservable")
            else:
                # The agent image is not trusted with the operator's checkout merely because
                # the benchmark needs its CLI version. Mount only an empty verifier-owned
                # directory. The image's normal ENTRYPOINT remains intact because legitimate
                # CLI images may need it for setup, but it has no caller files to mutate.
                with tempfile.TemporaryDirectory(prefix="stinger-agent-version-") as temporary:
                    version_workspace = Path(temporary)
                    version_workspace.chmod(0o700)
                    container_name = f"stinger-version-{uuid4().hex[:12]}"
                    effective_version = docker_argv(
                        agent_image_id,
                        version_workspace,
                        version_argv,
                        network=False,
                        name=container_name,
                        runtime=docker_runtime,
                    )
                    observed_cli_version = _command_output(
                        effective_version,
                        cwd=version_workspace,
                        issue="agent_cli_version_unobservable",
                        issues=issues,
                        environment=docker_environment(),
                        container_name=container_name,
                        docker_runtime=docker_runtime,
                    )
        except (
            AdapterSettingsError,
            AssertionError,
            OSError,
            ShellAdapterError,
            ValueError,
        ) as exc:
            issues.append(f"agent_invocation_settings_unresolved:{exc}")

    candidate = BenchmarkRuntimeProvenance(
        requested_provider=config.agent.provider,
        requested_model_id=config.agent.model,
        stinger_commit=stinger_commit,
        agent_cli_version=observed_cli_version,
        agent_container_image_id=agent_image_id,
        agent_container_repo_digests=agent_repo_digests,
        verification_image_id=verification_image_id,
        verification_image_repo_digests=verification_repo_digests,
        verification_image_policy_sha256=verification_image_policy_sha256,
        docker_client_sha256=(None if docker_runtime is None else docker_runtime.client_sha256),
        docker_runtime_fingerprint_sha256=(
            None if docker_runtime is None else docker_runtime.fingerprint_sha256
        ),
        docker_runtime_claim_boundary=(
            None if docker_runtime is None else DOCKER_RUNTIME_CLAIM_BOUNDARY
        ),
        resolved_agent_invocation=invocation,
        resolved_version_invocation=version_invocation,
        resolved_environment_names=environment_names,
        reasoning_effort=config.agent.reasoning_effort,
        inference_settings=config.agent.inference_settings,
        credential_isolation=credential_isolation,
        verified=True,
    )
    issues.extend(publication_pin_issues(metadata, candidate))
    issues.extend(canonical_local_provider_binding_issues(metadata, candidate))
    if docker_runtime is not None:
        try:
            verify_docker_runtime(docker_runtime)
        except DockerRuntimeError:
            issues.append("docker_runtime_changed")
    if implementation is not None and expected_stinger_commit is not None:
        try:
            final_implementation = verify_loaded_stinger_implementation(
                checkout,
                expected_commit=expected_stinger_commit,
                timeout=_PROBE_TIMEOUT_S,
            )
        except GitCheckoutError:
            issues.append("stinger_loaded_implementation_changed")
        else:
            if final_implementation != implementation:
                issues.append("stinger_loaded_implementation_changed")
    if issues:
        failed = candidate.model_copy(
            update={
                "verified": False,
                "verification_issues": tuple(dict.fromkeys(issues)),
            }
        )
        raise RuntimePreflightError(failed)
    if isinstance(adapter, CliAgentAdapter) and agent_image_id is not None:
        # Execute the immutable bytes that were inspected above. Keeping the mutable tag in
        # the adapter would permit a tag swap between preflight and the first model call.
        pinned_broker = adapter.config.credential_broker
        if pinned_broker is not None and broker_image_id is not None:
            pinned_broker = pinned_broker.model_copy(update={"image": broker_image_id})
        adapter.config = adapter.config.model_copy(
            update={
                "container_image": agent_image_id,
                "credential_broker": pinned_broker,
            }
        )
    return candidate


def _docker_image_identity(
    image: str,
    issue: str,
    issues: list[str],
    *,
    runtime: DockerRuntimeIdentity | None,
) -> tuple[str | None, tuple[str, ...]]:
    """Inspect Docker's immutable local image id and any registry manifest digests."""
    try:
        if runtime is None:
            raise DockerRuntimeError("Docker runtime is unavailable")
        return inspect_docker_image(image, runtime=runtime)
    except DockerRuntimeError:
        issues.append(issue)
        return None, ()


def _image_identity_matches(
    declared: str,
    image_id: str | None,
    repo_digests: tuple[str, ...],
) -> bool:
    """Return whether Docker's observed identity matches an immutable declaration."""
    return image_id == declared or any(item.rpartition("@")[2] == declared for item in repo_digests)


def _command_output(
    argv: list[str],
    *,
    cwd: Path,
    issue: str,
    issues: list[str],
    environment: dict[str, str] | None = None,
    container_name: str | None = None,
    docker_runtime: DockerRuntimeIdentity | None = None,
) -> str | None:
    """Run one local identity probe and return its exact stripped output."""
    passthrough = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR")
    env = (
        {key: os.environ[key] for key in passthrough if key in os.environ}
        if environment is None
        else environment
    )
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=_PROBE_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        _require_probe_container_absent(container_name, docker_runtime)
        issues.append(issue)
        return None
    except OSError:
        _require_probe_container_absent(container_name, docker_runtime)
        issues.append(issue)
        return None
    except BaseException:
        _require_probe_container_absent(container_name, docker_runtime)
        raise
    output = (completed.stdout or completed.stderr).strip()
    if completed.returncode != 0:
        _require_probe_container_absent(container_name, docker_runtime)
        issues.append(issue)
        return None
    if not output:
        issues.append(issue)
        return None
    return output


def _require_probe_container_absent(
    name: str | None,
    runtime: DockerRuntimeIdentity | None,
) -> None:
    """Prove an abnormal containerized identity probe left no named container."""
    if name is None:
        return
    if runtime is None:
        raise RuntimePreflightError(
            BenchmarkRuntimeProvenance(
                verification_issues=("agent_cli_version_container_termination_unverified",),
            )
        )
    try:
        terminate_docker_container(
            name,
            runtime=runtime,
            timeout=30,
        )
    except DockerRuntimeError:
        raise RuntimePreflightError(
            BenchmarkRuntimeProvenance(
                verification_issues=("agent_cli_version_container_termination_unverified",),
            )
        ) from None
