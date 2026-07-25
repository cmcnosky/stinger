"""Fixed, content-bound access to the local Docker runtime.

The benchmark uses Docker as a containment mechanism, so resolving ``docker`` through an
operator-controlled ``PATH`` would make every later image digest and containment statement
self-attested.  This module is the only production boundary that may launch the Docker
client.  It resolves the client from a small operating-system allowlist, hashes the exact
resolved executable, strips Docker/loader overrides from its environment, and records a
bounded client/context/server observation.

The resulting fingerprint is deliberately narrow.  It proves which local client bytes,
configured context endpoint, and daemon-reported identity Stinger observed.  It is not TPM
evidence and cannot prove that a machine administrator did not replace or emulate a daemon.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path

DOCKER_RUNTIME_CLAIM_BOUNDARY = (
    "exact fixed-path Docker client bytes plus bounded local context and daemon-reported "
    "identity; not TPM, daemon anti-fabrication, physical-host, or administrator-integrity proof"
)

_CLIENT_CANDIDATES = (
    Path("/usr/local/bin/docker"),
    Path("/usr/bin/docker"),
    Path("/opt/homebrew/bin/docker"),
    Path("/Applications/Docker.app/Contents/Resources/bin/docker"),
    Path("/snap/bin/docker"),
)
_FIXED_PATH = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"
_SAFE_BASE_ENVIRONMENT = ("LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT")
_EMPTY_DOCKER_CONFIG = "/var/empty"
_FORBIDDEN_ENVIRONMENT_PREFIXES = (
    "DOCKER_",
    "LD_",
    "DYLD_",
)
_FORBIDDEN_ENVIRONMENT_NAMES = frozenset(
    {
        "BASH_ENV",
        "ENV",
        "GIT_CONFIG",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "HOME",
        "PATH",
        "PYTHONPATH",
        "SHELLOPTS",
    }
)
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CONTAINER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_OBSERVATION_BYTES = 128 * 1024
_DEFAULT_TIMEOUT_SECONDS = 60
_CLEANUP_MAX_ATTEMPTS = 4
_CLEANUP_REQUIRED_ABSENCE_OBSERVATIONS = 2
_CLEANUP_SETTLE_SECONDS = 0.1


class DockerRuntimeError(Exception):
    """Raised when the fixed local Docker runtime cannot be proved or used."""


@dataclass(frozen=True, slots=True)
class DockerRuntimeIdentity:
    """Non-secret, bounded observation of one local Docker client and daemon."""

    client_path: str
    client_sha256: str
    client_version: str
    context_name: str
    context_endpoint: str = field(repr=False)
    context_endpoint_sha256: str
    server_platform: str
    server_version: str
    server_api_version: str
    server_os: str
    server_arch: str

    @property
    def fingerprint_sha256(self) -> str:
        """Return the canonical commitment used by reports and signed receipts."""
        return hashlib.sha256(_canonical_identity_bytes(self)).hexdigest()


@dataclass(frozen=True, slots=True)
class DockerImageIdentity:
    """Immutable image identity and daemon-reported target platform."""

    image_id: str
    repo_digests: tuple[str, ...]
    operating_system: str
    architecture: str

    @property
    def platform(self) -> str:
        """Return Docker's canonical ``os/architecture`` platform key."""
        return f"{self.operating_system}/{self.architecture}"


_active_runtime: DockerRuntimeIdentity | None = None


def resolve_docker_client() -> Path:
    """Resolve one executable Docker client from the fixed macOS/Linux allowlist."""
    for candidate in _CLIENT_CANDIDATES:
        try:
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except OSError:
            continue
        if stat.S_ISREG(metadata.st_mode) and os.access(resolved, os.X_OK):
            return resolved
    raise DockerRuntimeError("fixed Docker client is unavailable")


def docker_environment(
    source: Mapping[str, str] | None = None,
    *,
    forwarded_names: Sequence[str] = (),
) -> dict[str, str]:
    """Build the only environment permitted for a Docker client subprocess.

    ``forwarded_names`` is used by model-agent containers for explicitly configured API
    credentials and inference options.  Docker/context and dynamic-loader controls are
    never forwardable.
    """
    values = os.environ if source is None else source
    environment = {name: values[name] for name in _SAFE_BASE_ENVIRONMENT if name in values}
    environment["PATH"] = _FIXED_PATH
    environment["HOME"] = _EMPTY_DOCKER_CONFIG
    environment["DOCKER_CONFIG"] = _EMPTY_DOCKER_CONFIG
    for name in forwarded_names:
        if _ENVIRONMENT_NAME.fullmatch(name) is None:
            raise DockerRuntimeError("Docker forwarded environment name is invalid")
        if name in _FORBIDDEN_ENVIRONMENT_NAMES or name.startswith(_FORBIDDEN_ENVIRONMENT_PREFIXES):
            raise DockerRuntimeError(
                "Docker/context or loader environment overrides are prohibited"
            )
        if name not in values:
            raise DockerRuntimeError("Docker forwarded environment value is unavailable")
        environment[name] = values[name]
    return environment


def observe_docker_runtime() -> DockerRuntimeIdentity:
    """Observe and activate one exact local client/context/server identity."""
    global _active_runtime

    client = resolve_docker_client()
    client_sha256 = _hash_regular_file(client)
    context_result = _run_raw(
        client,
        ("context", "show"),
        timeout=_DEFAULT_TIMEOUT_SECONDS,
        discovery=True,
    )
    context_name = _single_line(context_result.stdout, label="Docker context")
    context_details = _run_raw(
        client,
        ("context", "inspect", context_name),
        timeout=_DEFAULT_TIMEOUT_SECONDS,
        discovery=True,
    )
    endpoint = _context_endpoint(context_details.stdout)
    version_result = _run_raw(
        client,
        ("--host", endpoint, "version", "--format", "{{json .}}"),
        timeout=_DEFAULT_TIMEOUT_SECONDS,
        discovery=False,
    )
    identity = _parse_runtime_identity(
        version_result.stdout,
        client=client,
        client_sha256=client_sha256,
        context_name=context_name,
        endpoint=endpoint,
    )
    if _hash_regular_file(client) != client_sha256:
        raise DockerRuntimeError("fixed Docker client changed during observation")
    _active_runtime = identity
    return identity


def active_docker_runtime() -> DockerRuntimeIdentity | None:
    """Return the most recently observed runtime without performing I/O."""
    return _active_runtime


def verify_docker_runtime(expected: DockerRuntimeIdentity) -> DockerRuntimeIdentity:
    """Re-observe Docker and require the exact prior identity."""
    observed = observe_docker_runtime()
    if observed != expected:
        raise DockerRuntimeError("Docker runtime identity changed")
    return observed


def docker_command_argv(
    arguments: Sequence[str],
    *,
    runtime: DockerRuntimeIdentity | None = None,
) -> list[str]:
    """Build an absolute Docker argv pinned to an observed context when available."""
    selected = runtime or _active_runtime
    client = resolve_docker_client()
    if selected is not None:
        if str(client) != selected.client_path or _hash_regular_file(client) != (
            selected.client_sha256
        ):
            raise DockerRuntimeError("fixed Docker client differs from the observed runtime")
        return [str(client), "--host", selected.context_endpoint, *arguments]
    return [str(client), *arguments]


def run_docker(
    arguments: Sequence[str],
    *,
    runtime: DockerRuntimeIdentity | None = None,
    source_environment: Mapping[str, str] | None = None,
    forwarded_names: Sequence[str] = (),
    timeout: int = _DEFAULT_TIMEOUT_SECONDS,
    cwd: Path | None = None,
    observe_if_missing: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run Docker through the fixed client and sanitized environment."""
    selected = runtime or _active_runtime
    if selected is None and observe_if_missing:
        selected = observe_docker_runtime()
    argv = docker_command_argv(arguments, runtime=selected)
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=docker_environment(
                source_environment,
                forwarded_names=forwarded_names,
            ),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DockerRuntimeError("fixed Docker client invocation failed") from exc
    return completed


def inspect_docker_image(
    image: str,
    *,
    runtime: DockerRuntimeIdentity | None = None,
) -> tuple[str, tuple[str, ...]]:
    """Return one image's immutable id and sorted registry digests."""
    identity = inspect_docker_image_identity(image, runtime=runtime)
    return identity.image_id, identity.repo_digests


def inspect_docker_image_identity(
    image: str,
    *,
    runtime: DockerRuntimeIdentity | None = None,
) -> DockerImageIdentity:
    """Return one image's immutable id, registry digests, and target platform."""
    if not image or image != image.strip():
        raise DockerRuntimeError("Docker image reference is invalid")
    selected = runtime or _active_runtime or observe_docker_runtime()
    completed = run_docker(
        ("image", "inspect", image),
        runtime=selected,
    )
    if completed.returncode != 0:
        raise DockerRuntimeError("Docker image identity is unavailable")
    try:
        raw = json.loads(completed.stdout)
        record = raw[0]
        image_id = record["Id"]
        repo_digests = record.get("RepoDigests") or []
        operating_system = record["Os"]
        architecture = record["Architecture"]
    except (json.JSONDecodeError, IndexError, KeyError, TypeError):
        raise DockerRuntimeError("Docker image identity is invalid") from None
    if (
        not isinstance(image_id, str)
        or not image_id.startswith("sha256:")
        or _SHA256.fullmatch(image_id.removeprefix("sha256:")) is None
        or not isinstance(repo_digests, list)
        or any(not isinstance(value, str) for value in repo_digests)
        or not isinstance(operating_system, str)
        or not operating_system
        or operating_system != operating_system.strip()
        or "/" in operating_system
        or not isinstance(architecture, str)
        or not architecture
        or architecture != architecture.strip()
        or "/" in architecture
    ):
        raise DockerRuntimeError("Docker image identity is invalid")
    return DockerImageIdentity(
        image_id=image_id,
        repo_digests=tuple(sorted(repo_digests)),
        operating_system=operating_system,
        architecture=architecture,
    )


def terminate_docker_container(
    name: str,
    *,
    runtime: DockerRuntimeIdentity,
    timeout: int = _DEFAULT_TIMEOUT_SECONDS,
) -> None:
    """Force-remove one timed-out container and prove its exact name is absent.

    A timeout in a local Docker client kills only that client. A ``run`` container can keep
    executing, while a timed-out ``create`` request can leave a stopped container behind.
    The daemon may also finish processing the abandoned request just after the first cleanup
    observation. This helper therefore force-removes by exact verifier-generated name and
    requires two consecutive, bounded ``docker ps --all`` absence observations before
    accepting cleanup. A nonzero ``rm`` is acceptable only when the independent inventory
    proves the name absent; ``--rm`` may already have removed a completed run container.

    Args:
        name: Exact verifier-generated container name.
        runtime: Docker identity that launched the container.
        timeout: Independent ceiling for each cleanup observation.

    Raises:
        DockerRuntimeError: If exact-name absence or the fixed runtime cannot be verified.
    """
    if _CONTAINER_NAME.fullmatch(name) is None:
        raise DockerRuntimeError("Docker container name is invalid")
    consecutive_absence_observations = 0
    pending_interrupt: BaseException | None = None
    completed_attempts = 0
    maximum_attempts = _CLEANUP_MAX_ATTEMPTS
    while completed_attempts < maximum_attempts:
        try:
            # The remove status is not authoritative: an auto-removed or never-created
            # container legitimately returns nonzero. The independent all-state inventory is
            # the safety decision. A transient client failure on remove therefore cannot
            # prevent the independent inventory attempt, and a transient inventory failure
            # consumes one bounded attempt instead of abandoning cleanup immediately.
            with suppress(DockerRuntimeError):
                run_docker(
                    ("rm", "--force", name),
                    runtime=runtime,
                    timeout=timeout,
                    observe_if_missing=False,
                )
            remaining = run_docker(
                ("ps", "--all", "--quiet", "--filter", f"name=^/{name}$"),
                runtime=runtime,
                timeout=timeout,
                observe_if_missing=False,
            )
        except DockerRuntimeError:
            completed_attempts += 1
            consecutive_absence_observations = 0
        except BaseException as exc:
            if isinstance(exc, Exception):
                raise
            if pending_interrupt is not None:
                raise DockerRuntimeError(
                    "Docker container cleanup proof was repeatedly interrupted"
                ) from None
            pending_interrupt = exc
            maximum_attempts += _CLEANUP_REQUIRED_ABSENCE_OBSERVATIONS
            consecutive_absence_observations = 0
            continue
        else:
            completed_attempts += 1
            if remaining.returncode != 0:
                raise DockerRuntimeError("timed-out Docker container inventory failed")
            if remaining.stdout.strip():
                consecutive_absence_observations = 0
            else:
                consecutive_absence_observations += 1
                if consecutive_absence_observations >= _CLEANUP_REQUIRED_ABSENCE_OBSERVATIONS:
                    break
        if completed_attempts < maximum_attempts:
            try:
                time.sleep(_CLEANUP_SETTLE_SECONDS)
            except BaseException as exc:
                if isinstance(exc, Exception):
                    raise
                if pending_interrupt is not None:
                    raise DockerRuntimeError(
                        "Docker container cleanup proof was repeatedly interrupted"
                    ) from None
                pending_interrupt = exc
                maximum_attempts += _CLEANUP_REQUIRED_ABSENCE_OBSERVATIONS
                consecutive_absence_observations = 0
    else:
        raise DockerRuntimeError("timed-out Docker container absence was not verified")

    runtime_verification_attempts = 2 if pending_interrupt is None else 1
    runtime_verified = False
    for _attempt in range(runtime_verification_attempts):
        try:
            verify_docker_runtime(runtime)
        except BaseException as exc:
            if isinstance(exc, Exception):
                raise
            if pending_interrupt is not None:
                raise DockerRuntimeError(
                    "Docker runtime identity cleanup proof was repeatedly interrupted"
                ) from None
            pending_interrupt = exc
        else:
            runtime_verified = True
            break
    if not runtime_verified:
        raise DockerRuntimeError("Docker runtime identity cleanup proof was interrupted")
    if pending_interrupt is not None:
        raise pending_interrupt


def _run_raw(
    client: Path,
    arguments: Sequence[str],
    *,
    timeout: int,
    discovery: bool,
) -> subprocess.CompletedProcess[str]:
    """Run an observation command before a runtime identity exists."""
    try:
        completed = subprocess.run(
            [str(client), *arguments],
            env=(_docker_discovery_environment() if discovery else docker_environment()),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DockerRuntimeError("Docker runtime observation failed") from exc
    if completed.returncode != 0:
        raise DockerRuntimeError("Docker runtime observation failed")
    if len(completed.stdout.encode("utf-8")) > _MAX_OBSERVATION_BYTES:
        raise DockerRuntimeError("Docker runtime observation exceeded its size limit")
    return completed


def _single_line(value: str, *, label: str) -> str:
    normalized = value.strip()
    if (
        not normalized
        or "\n" in normalized
        or "\r" in normalized
        or "\x00" in normalized
        or len(normalized.encode("utf-8")) > 512
    ):
        raise DockerRuntimeError(f"{label} is invalid")
    return normalized


def _context_endpoint(value: str) -> str:
    try:
        raw = json.loads(value)
        record = raw[0]
        docker_endpoint = record["Endpoints"]["docker"]
        endpoint = docker_endpoint["Host"]
        tls_material = record.get("TLSMaterial") or {}
        skip_tls_verify = docker_endpoint.get("SkipTLSVerify", False)
    except (json.JSONDecodeError, IndexError, KeyError, TypeError):
        raise DockerRuntimeError("Docker context endpoint is invalid") from None
    normalized = _single_line(endpoint, label="Docker context endpoint")
    if not normalized.startswith("unix:///") or tls_material or skip_tls_verify is not False:
        raise DockerRuntimeError("Docker containment requires a local non-TLS Unix-socket context")
    return normalized


def _parse_runtime_identity(
    value: str,
    *,
    client: Path,
    client_sha256: str,
    context_name: str,
    endpoint: str,
) -> DockerRuntimeIdentity:
    try:
        raw = json.loads(value)
        client_record = raw["Client"]
        server_record = raw["Server"]
        platform = server_record.get("Platform") or {}
        identity = DockerRuntimeIdentity(
            client_path=str(client),
            client_sha256=client_sha256,
            client_version=_bounded_field(client_record["Version"], "Docker client version"),
            context_name=context_name,
            context_endpoint=endpoint,
            context_endpoint_sha256=hashlib.sha256(endpoint.encode("utf-8")).hexdigest(),
            server_platform=_bounded_field(
                platform.get("Name") or "unknown",
                "Docker server platform",
            ),
            server_version=_bounded_field(server_record["Version"], "Docker server version"),
            server_api_version=_bounded_field(
                server_record["ApiVersion"],
                "Docker server API version",
            ),
            server_os=_bounded_field(server_record["Os"], "Docker server OS"),
            server_arch=_bounded_field(server_record["Arch"], "Docker server architecture"),
        )
    except (KeyError, TypeError):
        raise DockerRuntimeError("Docker version observation is invalid") from None
    return identity


def _bounded_field(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise DockerRuntimeError(f"{label} is invalid")
    return _single_line(value, label=label)


def _hash_regular_file(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise DockerRuntimeError("fixed Docker client is unreadable") from None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise DockerRuntimeError("fixed Docker client is not a regular file")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
    except OSError:
        raise DockerRuntimeError("fixed Docker client could not be hashed") from None
    finally:
        os.close(descriptor)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise DockerRuntimeError("fixed Docker client changed while hashing")
    return digest.hexdigest()


def _canonical_identity_bytes(identity: DockerRuntimeIdentity) -> bytes:
    payload = {
        "claim_boundary": DOCKER_RUNTIME_CLAIM_BOUNDARY,
        "client_path": identity.client_path,
        "client_sha256": identity.client_sha256,
        "client_version": identity.client_version,
        "context_name": identity.context_name,
        "context_endpoint_sha256": identity.context_endpoint_sha256,
        "server_api_version": identity.server_api_version,
        "server_arch": identity.server_arch,
        "server_os": identity.server_os,
        "server_platform": identity.server_platform,
        "server_version": identity.server_version,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _docker_discovery_environment() -> dict[str, str]:
    """Allow only HOME while discovering the operator-selected local context.

    The resulting endpoint is immediately pinned into argv and every later Docker call uses
    an empty verifier-owned config, so subsequent config mutation cannot alter execution.
    """
    environment = docker_environment()
    home = os.environ.get("HOME")
    if home:
        environment["HOME"] = home
        environment.pop("DOCKER_CONFIG", None)
    return environment


__all__ = [
    "DOCKER_RUNTIME_CLAIM_BOUNDARY",
    "DockerRuntimeError",
    "DockerRuntimeIdentity",
    "active_docker_runtime",
    "docker_command_argv",
    "docker_environment",
    "inspect_docker_image",
    "observe_docker_runtime",
    "resolve_docker_client",
    "run_docker",
    "terminate_docker_container",
    "verify_docker_runtime",
]
