"""Mechanical runtime provenance preflight for benchmark-capable runs."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from stinger.adapters.base import AgentAdapter
from stinger.adapters.cli_base import AdapterSettingsError, CliAgentAdapter
from stinger.adapters.shell import ShellAdapterError
from stinger.benchmark.protocol import BenchmarkRuntimeProvenance, publication_pin_issues
from stinger.config import RunConfig
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
) -> BenchmarkRuntimeProvenance:
    """Observe and verify the exact local runtime before a benchmark run starts.

    Args:
        config: Fully resolved run configuration with benchmark mode enabled.
        adapter: Constructed agent adapter.
        workdir: Existing directory used for the non-network CLI version probe.
        repository: Stinger checkout whose exact HEAD is being run. Defaults to this module's
            repository root.

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
    stinger_commit = _command_output(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        cwd=checkout,
        issue="stinger_commit_unobservable",
        issues=issues,
    )
    if not _git_worktree_clean(checkout):
        issues.append("stinger_worktree_dirty")

    agent_image_id: str | None = None
    agent_repo_digests: tuple[str, ...] = ()
    verification_image_id: str | None = None
    verification_repo_digests: tuple[str, ...] = ()
    if config.isolation is not Isolation.DOCKER:
        issues.append("verification_image_not_containerized")
    else:
        verification_image_id, verification_repo_digests = _docker_image_identity(
            config.image,
            "verification_image_unobservable",
            issues,
        )
    if config.agent.container_image is None:
        issues.append("agent_not_containerized")
    else:
        agent_image_id, agent_repo_digests = _docker_image_identity(
            config.agent.container_image,
            "agent_container_image_unobservable",
            issues,
        )

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
            effective_version = (
                version_argv
                if config.agent.container_image is None
                else docker_argv(
                    config.agent.container_image,
                    workdir,
                    version_argv,
                    network=False,
                )
            )
            # Record the exact command *inside* the pinned agent image, not Docker's host
            # wrapper. The wrapper contains the operator's absolute workdir mount, which is
            # machine-private and irrelevant once the image digest and containerized
            # preflight are recorded. ``effective_version`` is still what executes.
            version_invocation = tuple(version_argv)
            observed_cli_version = _command_output(
                effective_version,
                cwd=workdir,
                issue="agent_cli_version_unobservable",
                issues=issues,
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
        resolved_agent_invocation=invocation,
        resolved_version_invocation=version_invocation,
        resolved_environment_names=environment_names,
        reasoning_effort=config.agent.reasoning_effort,
        inference_settings=config.agent.inference_settings,
        verified=True,
    )
    issues.extend(publication_pin_issues(metadata, candidate))
    if issues:
        failed = candidate.model_copy(
            update={
                "verified": False,
                "verification_issues": tuple(dict.fromkeys(issues)),
            }
        )
        raise RuntimePreflightError(failed)
    return candidate


def _git_worktree_clean(repository: Path) -> bool:
    """Require HEAD to identify the exact source rather than only its committed ancestor."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), "status", "--porcelain", "--untracked-files=all"],
            cwd=repository,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=_PROBE_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0 and not completed.stdout.strip()


def _docker_image_identity(
    image: str,
    issue: str,
    issues: list[str],
) -> tuple[str | None, tuple[str, ...]]:
    """Inspect Docker's immutable local image id and any registry manifest digests."""
    try:
        completed = subprocess.run(
            ["docker", "image", "inspect", image],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=_PROBE_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        issues.append(issue)
        return None, ()
    if completed.returncode != 0:
        issues.append(issue)
        return None, ()
    try:
        raw: Any = json.loads(completed.stdout)
        record = raw[0]
        image_id = record["Id"]
        repo_digests = record.get("RepoDigests") or []
        if not isinstance(image_id, str) or not isinstance(repo_digests, list):
            raise TypeError
        typed_repo_digests = tuple(sorted(str(value) for value in repo_digests))
    except (json.JSONDecodeError, IndexError, KeyError, TypeError):
        issues.append(issue)
        return None, ()
    return image_id, typed_repo_digests


def _command_output(
    argv: list[str],
    *,
    cwd: Path,
    issue: str,
    issues: list[str],
) -> str | None:
    """Run one local identity probe and return its exact stripped output."""
    passthrough = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR")
    env = {key: os.environ[key] for key in passthrough if key in os.environ}
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
    except (OSError, subprocess.TimeoutExpired):
        issues.append(issue)
        return None
    output = (completed.stdout or completed.stderr).strip()
    if completed.returncode != 0 or not output:
        issues.append(issue)
        return None
    return output
