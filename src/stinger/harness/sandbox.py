"""Isolation and repository-state capture (SPEC.md §2, §7 steps 1, 2, 4).

Two isolation modes:

* ``Isolation.DOCKER`` — the real mode. Every command Stinger runs to *verify* a scenario
  (the held-out completion check, a detector's test re-run) executes in its own throwaway
  container with the network disabled, so a verification result can never be influenced by
  the host or by anything the agent reached over the wire.
* ``Isolation.LOCAL`` — development only. The workdir is an isolated scratch git tree and
  verification commands run as host subprocesses. This mode MUST refuse the ``X`` (safety)
  family, because those scenarios seed bait secrets and exfiltration lures that have no
  business running unconfined on a developer's machine.

Workdir materialisation is identical in both modes; only where commands *execute* differs.
That keeps `capture` a pure host-side filesystem walk, which is what makes `RepoState`
deterministic and diffable without shelling out to git.

Determinism note (AGENTS.md rule 6): the seed commit is created with pinned author and
committer identity and a fixed date, so `RepoState.head_commit` is a function of the
scenario content alone. Nothing here reads the wall clock.
"""

from __future__ import annotations

import difflib
import hashlib
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from uuid import uuid4

from stinger.benchmark.verification_image import (
    VerificationImagePolicy,
    VerificationImagePolicyError,
    compiled_verification_image_policy,
    verify_approved_verification_image,
)
from stinger.detectors.base import RepoState
from stinger.docker_runtime import (
    DockerRuntimeError,
    DockerRuntimeIdentity,
    docker_command_argv,
    docker_environment,
    inspect_docker_image,
    observe_docker_runtime,
    terminate_docker_container,
    verify_docker_runtime,
)
from stinger.models import ExecResult, Family
from stinger.scenario.manifest import ScenarioManifest

__all__ = [
    "DEFAULT_IMAGE",
    "ExecResult",
    "Isolation",
    "Sandbox",
    "SandboxError",
    "apply_overlay",
    "capture",
    "diff_states",
    "docker_argv",
]

DEFAULT_IMAGE = "stinger-runner:1"
"""Container image for verification commands. Overridable per run; part of the fingerprint.

Built from `docker/runner.Dockerfile`, NOT a bare `python:3.12-slim`. Verification runs with
the network disabled, so everything a check needs must already be in the image, and the
official Python images ship no pytest. That mattered more than it sounds: a completion check
that fails because pytest is missing looks exactly like one that fails because the agent did
not do the work, so the wrong image does not break a run visibly — it silently scores every
scenario as a failure. `preflight` exists to make that impossible.
"""

PREFLIGHT_MODULES = ("pytest",)
"""What `preflight` requires the verification image to provide. v1's corpus is Python-only
(SPEC.md §6 [OPEN]), and every scenario's completion check and suite re-run needs pytest."""

_EPHEMERAL_DIRS = frozenset(
    {".git", "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache", ".venv", "node_modules"}
)
"""Tool droppings excluded from capture. Excluded identically before and after, so their
presence or absence can never change a detector's verdict."""

_EPHEMERAL_SUFFIXES = (".pyc", ".pyo")

_MAX_CAPTURED_BYTES = 1 << 20
"""Per-file ceiling on inlined content. Larger files are hashed but land in
`unreadable_files`, so detectors needing their text degrade to review, never to a pass."""

_TIMEOUT_EXIT_CODE = 124
"""Conventional shell exit code for a timeout (matches coreutils `timeout`)."""

_PREFLIGHT_TIMEOUT_S = 120
_PREFLIGHT_PREAMBLE = "refusing to start: the verification image is not usable"


def _build_hint(image: str) -> str:
    """The exact command that fixes a failed preflight.

    Points at Stinger's own image rather than offering to re-tag whatever the operator
    configured: if someone set `image:` deliberately, telling them to overwrite that tag with
    Stinger's Dockerfile is the wrong advice.
    """
    lines = [
        "Fix it by building Stinger's verification image:",
        '    stinger_runner_build_dir="$(mktemp -d)"',
        "    docker buildx build --no-cache --provenance=false \\",
        "      --build-arg SOURCE_DATE_EPOCH=0 \\",
        f"      --platform linux/arm64 -t {DEFAULT_IMAGE} \\",
        "      --output type=docker,rewrite-timestamp=true,"
        'dest="$stinger_runner_build_dir/stinger-runner.tar" \\',
        "      -f docker/runner.Dockerfile docker/",
        '    docker load --input "$stinger_runner_build_dir/stinger-runner.tar"',
        "    # Use --platform linux/amd64 on an amd64 Docker host.",
    ]
    if image != DEFAULT_IMAGE:
        lines.append(
            f"...then remove `image: {image}` from stinger.yaml, or add "
            f"{', '.join(PREFLIGHT_MODULES)} to that image yourself."
        )
    lines.append(
        "A bare python image will not do: verification runs with the network disabled, so "
        "everything a completion check needs must already be inside. For development, "
        "--local skips containers entirely (and refuses the X safety family)."
    )
    return "\n".join(lines)


_GIT_ENV: Mapping[str, str] = {
    "GIT_AUTHOR_NAME": "stinger",
    "GIT_AUTHOR_EMAIL": "stinger@localhost",
    "GIT_COMMITTER_NAME": "stinger",
    "GIT_COMMITTER_EMAIL": "stinger@localhost",
    "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
    "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "HOME": "/nonexistent",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "XDG_CONFIG_HOME": "/nonexistent",
}
_FIXED_GIT = Path("/usr/bin/git")


class SandboxError(Exception):
    """Raised when isolation cannot be established or a workdir is unusable.

    The runner treats this as a harness failure and resolves the scenario to
    `Outcome.ERROR` — never to a favourable outcome (SPEC.md §1.1).
    """


class Isolation(StrEnum):
    """How Stinger isolates a scenario execution (SPEC.md §2)."""

    DOCKER = "docker"
    LOCAL = "local"  # development only; refuses the X family


class Sandbox:
    """Materialises scenario workdirs and runs verification commands under isolation."""

    def __init__(self, isolation: Isolation = Isolation.DOCKER, image: str = DEFAULT_IMAGE) -> None:
        """Configure isolation.

        Args:
            isolation: DOCKER for real runs, LOCAL for development (refuses family X).
            image: Container image used for verification commands in DOCKER mode.
        """
        self.isolation = isolation
        self.image = image
        self._docker_runtime: DockerRuntimeIdentity | None = None
        self._verification_image_id: str | None = None
        self._verification_image_repo_digests: tuple[str, ...] = ()
        self._verification_image_policy_sha256: str | None = None

    def preflight_benchmark(
        self,
        repository: Path,
        *,
        policy: VerificationImagePolicy | None = None,
    ) -> None:
        """Approve Protocol 2 source, platform, and image bytes before any container starts.

        Ordinary development runs retain :meth:`preflight` and may use a custom verifier.
        Any benchmark lifecycle operation must use this stronger boundary. The signed
        protocol policy is the trust root; importing pytest from an arbitrary image is not
        evidence that its verification result is honest.
        """
        if self.isolation is not Isolation.DOCKER:
            raise SandboxError("benchmark verification requires Docker isolation")
        selected_policy = policy or compiled_verification_image_policy()
        try:
            approved = verify_approved_verification_image(
                repository=repository,
                image=self.image,
                policy=selected_policy,
                docker_runtime=self._docker_runtime,
            )
        except VerificationImagePolicyError as exc:
            raise SandboxError(
                f"{_PREFLIGHT_PREAMBLE}: Protocol 2 verification-image policy rejected "
                f"the run: {exc}"
            ) from exc
        self._docker_runtime = approved.docker_runtime
        self._verification_image_id = approved.image.image_id
        self._verification_image_repo_digests = approved.image.repo_digests
        self._verification_image_policy_sha256 = approved.policy_sha256
        self.preflight()

    def prepare(self, scenario_dir: Path, manifest: ScenarioManifest, dest: Path) -> Path:
        """Materialise an isolated working copy of a scenario's seed repo (SPEC.md §7 step 1).

        Copies `seed_repo` into `dest`, writes the scenario's seeded house rules to
        `dest/AGENTS.md` when the manifest declares them, and git-initialises the result so
        the agent under test sees a real repository. The house rules are written *before*
        the `before` snapshot is taken, so an agent that edits its own house rules shows up
        as a changed path (family G).

        Args:
            scenario_dir: The scenario's directory (contains manifest.yaml and seed_repo/).
            manifest: The scenario's validated manifest.
            dest: Where to materialise the workdir. Created if absent; MUST be empty.

        Returns:
            The prepared workdir, which is `dest`.

        Raises:
            SandboxError: If LOCAL isolation is used for the X family, the seed repo is
                missing, or `dest` already holds files.
        """
        # `==` rather than `is`: a safety guard must not hinge on enum identity, which an
        # unvalidated manifest (e.g. one built with model_copy) would not preserve.
        if self.isolation is Isolation.LOCAL and manifest.family == Family.X:
            raise SandboxError(
                f"scenario {manifest.id!r} is family X (safety/exfiltration) and MUST NOT run "
                "under --local isolation; it seeds bait secrets and exfiltration lures that "
                "require container isolation (SPEC.md §2)"
            )

        seed = scenario_dir / manifest.seed_repo
        if not seed.is_dir():
            raise SandboxError(f"scenario {manifest.id!r} has no seed repo at {seed}")

        dest.mkdir(parents=True, exist_ok=True)
        if any(dest.iterdir()):
            raise SandboxError(f"workdir {dest} is not empty; refusing to overwrite")

        shutil.copytree(seed, dest, dirs_exist_ok=True, ignore=_ignore_ephemeral)
        if manifest.seeded_house_rules is not None:
            (dest / "AGENTS.md").write_text(manifest.seeded_house_rules, encoding="utf-8")
        _git_seed(dest)
        return dest

    def capture(self, workdir: Path) -> RepoState:
        """Snapshot the working tree (SPEC.md §7 steps 2 and 4). See `capture`."""
        return capture(workdir)

    def preflight(self) -> None:
        """Refuse to start a run the verification image cannot actually serve.

        Called once before any scenario runs. Without it, an image missing pytest produces a
        completion check that exits non-zero for a reason that has nothing to do with the
        agent — and downstream that is indistinguishable from "the agent did not fix the
        bug". Every scenario would score as a failure and the report would look plausible.
        That is the most dangerous shape a bug can take in a measurement tool, so this check
        is loud, early, and not skippable.

        A no-op under LOCAL isolation, where commands run in the host environment that is
        already running Stinger and its test dependencies.

        Raises:
            SandboxError: If Docker is unavailable, the image is missing, or the image cannot
                import something in `PREFLIGHT_MODULES`. The message names the build command.
        """
        if self.isolation is Isolation.LOCAL:
            return

        try:
            self._docker_runtime = (
                observe_docker_runtime()
                if self._docker_runtime is None
                else verify_docker_runtime(self._docker_runtime)
            )
            if self._verification_image_id is None:
                (
                    self._verification_image_id,
                    self._verification_image_repo_digests,
                ) = inspect_docker_image(self.image, runtime=self._docker_runtime)
        except DockerRuntimeError as exc:
            raise SandboxError(f"{_PREFLIGHT_PREAMBLE}: {exc}\n{_build_hint(self.image)}") from exc
        probe = "; ".join(f"import {module}" for module in PREFLIGHT_MODULES)
        try:
            with tempfile.TemporaryDirectory(prefix="stinger-verifier-preflight-") as temporary:
                preflight_workspace = Path(temporary)
                preflight_workspace.chmod(0o700)
                result = self.run_command(
                    preflight_workspace,
                    ["python", "-c", probe],
                    _PREFLIGHT_TIMEOUT_S,
                )
        except (OSError, SandboxError) as exc:
            raise SandboxError(f"{_PREFLIGHT_PREAMBLE}: {exc}\n{_build_hint(self.image)}") from exc

        if not result.ok:
            detail = (result.stderr or result.stdout).strip()[-400:] or "(no output)"
            raise SandboxError(
                f"{_PREFLIGHT_PREAMBLE}: image {self.image!r} could not import "
                f"{', '.join(PREFLIGHT_MODULES)} — {detail}\n{_build_hint(self.image)}"
            )
        self.verify_runtime_unchanged()

    def run_command(
        self, workdir: Path, argv: Sequence[str], timeout_s: int, *, network: bool = False
    ) -> ExecResult:
        """Run a verification command against `workdir` under this sandbox's isolation.

        This is the *verification* channel — the held-out completion check and any detector
        that needs to re-run a suite. It is network-isolated by default and MUST stay that
        way for anything whose result feeds scoring (SPEC.md §2: no network in the scoring
        path). Driving the agent under test is a separate concern and belongs to adapters
        (SPEC.md §5); adapters are the only component permitted to invoke the agent.

        A timeout is reported as `timed_out=True` with exit code 124 rather than raising, so
        the caller can resolve it to a non-scoring outcome with evidence.

        Args:
            workdir: The prepared workdir; becomes the command's working directory.
            argv: Command and arguments. Not shell-interpreted.
            timeout_s: Wall-clock ceiling for the command.
            network: Allow the container network. Only ever True for non-scoring uses.

        Returns:
            What was observed: the effective argv, exit code, streams, and timeout flag.

        Raises:
            SandboxError: If the command could not be launched at all.
        """
        if self.isolation is Isolation.DOCKER and (
            self._docker_runtime is None or self._verification_image_id is None
        ):
            raise SandboxError(
                "Docker sandbox preflight has not established a fixed runtime identity"
            )
        container_name = (
            f"stinger-verifier-{uuid4().hex[:12]}" if self.isolation is Isolation.DOCKER else None
        )
        try:
            effective = self._effective_argv(
                workdir,
                argv,
                network=network,
                name=container_name,
            )
            environment = (
                _command_env()
                if self.isolation is Isolation.LOCAL
                else docker_environment(_command_env())
            )
        except DockerRuntimeError as exc:
            raise SandboxError(f"fixed Docker runtime is unavailable: {exc}") from exc
        try:
            completed = _run_sandbox_process(
                effective,
                cwd=workdir,
                timeout=timeout_s,
                environment=environment,
            )
        except subprocess.TimeoutExpired as exc:
            _require_verification_container_absent(
                container_name,
                self._docker_runtime,
                context="verification command timed out",
            )
            return ExecResult(
                argv=list(effective),
                exit_code=_TIMEOUT_EXIT_CODE,
                stdout=_as_text(exc.stdout),
                stderr=_as_text(exc.stderr),
                timed_out=True,
            )
        except OSError as exc:
            _require_verification_container_absent(
                container_name,
                self._docker_runtime,
                context="verification command launch failed",
            )
            raise SandboxError(f"could not launch {list(effective)!r}: {exc}") from exc
        except BaseException:
            _require_verification_container_absent(
                container_name,
                self._docker_runtime,
                context="verification command was interrupted",
            )
            raise
        if completed.returncode != 0:
            # A nonzero inner command normally makes `docker run` return nonzero after
            # `--rm` has done its work. A killed/crashed Docker client has the same shape,
            # however, and may leave the container running. Prove absence before preserving
            # its streams as verification evidence.
            _require_verification_container_absent(
                container_name,
                self._docker_runtime,
                context="verification Docker client ended abnormally",
            )
        return ExecResult(
            argv=list(effective),
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    def _effective_argv(
        self,
        workdir: Path,
        argv: Sequence[str],
        *,
        network: bool,
        name: str | None = None,
    ) -> list[str]:
        """The command as actually invoked: bare in LOCAL mode, container-wrapped in DOCKER."""
        if self.isolation is Isolation.LOCAL:
            return list(argv)
        return docker_argv(
            self._verification_image_id or self.image,
            workdir,
            argv,
            network=network,
            name=name,
            runtime=self._docker_runtime,
            entrypoint="",
        )

    @property
    def docker_runtime_identity(self) -> DockerRuntimeIdentity | None:
        """Return the instance-bound runtime established by Docker preflight."""
        return self._docker_runtime

    @property
    def verification_image_identity(self) -> tuple[str, tuple[str, ...]] | None:
        """Return the immutable image observation used by this sandbox instance."""
        if self._verification_image_id is None:
            return None
        return self._verification_image_id, self._verification_image_repo_digests

    @property
    def verification_image_policy_sha256(self) -> str | None:
        """Return the signed policy binding established by benchmark preflight."""
        return self._verification_image_policy_sha256

    def verify_runtime_unchanged(self) -> None:
        """Re-observe and require the exact instance-bound runtime after contained work."""
        if self.isolation is Isolation.LOCAL:
            return
        if self._docker_runtime is None or self._verification_image_id is None:
            raise SandboxError(
                "Docker sandbox preflight has not established a fixed runtime identity"
            )
        try:
            self._docker_runtime = verify_docker_runtime(self._docker_runtime)
        except DockerRuntimeError as exc:
            raise SandboxError("Docker runtime changed after preflight") from exc


def _require_verification_container_absent(
    name: str | None,
    runtime: DockerRuntimeIdentity | None,
    *,
    context: str,
) -> None:
    """Prove an abnormal verification invocation left no named container."""
    if name is None:
        return
    assert runtime is not None
    try:
        terminate_docker_container(
            name,
            runtime=runtime,
            timeout=30,
        )
    except DockerRuntimeError as cleanup_error:
        raise SandboxError(
            f"{context} and container termination could not be verified"
        ) from cleanup_error


def docker_argv(
    image: str,
    workdir: Path,
    argv: Sequence[str],
    *,
    network: bool = False,
    network_name: str | None = None,
    auto_remove: bool = True,
    hardened_network_client: bool = False,
    forward_env: Sequence[str] = (),
    read_only_mounts: Mapping[str, str] | None = None,
    name: str | None = None,
    runtime: DockerRuntimeIdentity | None = None,
    entrypoint: str | None = None,
) -> list[str]:
    """Build the `docker run` invocation for one throwaway verification container.

    Pure function of its arguments so the container contract is unit-testable on machines
    without Docker. One container per execution, removed on exit, network off unless
    explicitly enabled (SPEC.md §2).

    Args:
        image: Container image to run.
        workdir: Host directory bind-mounted at /work and used as the working directory.
        argv: Command and arguments to run inside the container.
        network: When False (the default and the only setting valid for scoring), the
            container gets `--network none` unless ``network_name`` selects a pre-created
            internal network.
        network_name: Exact Docker network for a credential-brokered agent. The caller must
            have created and verified it as internal before using it. It is mutually
            exclusive with unrestricted ``network=True``.
        auto_remove: Remove the container after exit. Credential-isolated agent runs retain
            the stopped container briefly so the broker controller can inspect its exact
            environment, mounts, image, and network before verified cleanup.
        hardened_network_client: Drop all Linux capabilities, prohibit privilege escalation,
            and disable IPv4/IPv6 forwarding. Valid only on a named broker network.
        forward_env: Names of environment variables to forward from this process into the
            container. Names only — never `NAME=VALUE`. Docker reads the value from the
            `docker` process's own environment, which keeps a credential out of the argv
            this function returns. That matters because the argv is recorded verbatim in
            `ExecResult.argv` and lands in the reproducibility package, and it is visible in
            the host process list for the lifetime of the run. Verification containers pass
            nothing here; they have no credentials and no network.
        read_only_mounts: Extra `host path -> container path` bind mounts, all `:ro`. Only
            the agent container uses this, and only for a credential directory a CLI reads
            from disk. Read-only is not a detail: the agent under test is the untrusted party
            here, and a writable mount would hand it a channel out of the container.
        name: Container name, for callers that may need to stop the container from outside.
            A budget timeout kills only the local `docker run` client; without a name there
            is no handle to stop the container itself, and a contained agent would keep
            running — with network access — past its wall-clock ceiling.
        entrypoint: Explicit image entrypoint override. Verification sandboxes pass the
            empty string so Docker executes the supplied verification argv directly instead
            of trusting an image-authored ENTRYPOINT. Agent containers leave this unset
            because their reviewed entrypoint may perform required credential setup.

    Returns:
        The full argv for `subprocess.run`.
    """
    if network and network_name is not None:
        raise ValueError("unrestricted and named Docker network modes are mutually exclusive")
    if hardened_network_client and network_name is None:
        raise ValueError("hardened network clients require one named internal network")
    if network_name is not None and (
        not network_name
        or network_name != network_name.strip()
        or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789_.-" for character in network_name
        )
    ):
        raise ValueError("Docker network name is invalid")

    wrapper = ["run"]
    if auto_remove:
        wrapper.append("--rm")
    if entrypoint is not None:
        wrapper += ["--entrypoint", entrypoint]
    wrapper += [
        "--workdir",
        "/work",
        "--volume",
        f"{workdir.resolve()}:/work",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--env",
        "PYTHONHASHSEED=0",
        # The container's HOME must be somewhere it can write. Tools that cache in $HOME
        # otherwise fail in ways that look like the scenario failing.
        "--env",
        "HOME=/tmp",
    ]
    if name is not None:
        wrapper += ["--name", name]
    for host_path, container_path in sorted((read_only_mounts or {}).items()):
        wrapper += ["--volume", f"{Path(host_path).resolve()}:{container_path}:ro"]
    for env_name in forward_env:
        wrapper += ["--env", env_name]
    if hardened_network_client:
        wrapper += [
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--no-healthcheck",
            "--dns",
            "127.0.0.1",
            "--dns-search=.",
            "--dns-option",
            "timeout:1",
            "--dns-option",
            "attempts:1",
            "--sysctl",
            "net.ipv4.conf.all.forwarding=0",
            "--sysctl",
            "net.ipv6.conf.all.forwarding=0",
        ]
    wrapper += _user_mapping()
    if network_name is not None:
        wrapper += ["--network", network_name]
    elif not network:
        wrapper += ["--network", "none"]
    return docker_command_argv([*wrapper, image, *argv], runtime=runtime)


def _run_sandbox_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    timeout: int,
    environment: Mapping[str, str],
) -> subprocess.CompletedProcess[str]:
    """Launch one verification command through the narrow testable process seam."""
    return subprocess.run(
        list(argv),
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=dict(environment),
        check=False,
    )


def _user_mapping() -> list[str]:
    """Run the container as the invoking user, not root.

    On Linux a container runs as root by default, so anything it writes into the bind-mounted
    workdir — a `.pytest_cache`, a coverage file, a build artefact — comes back root-owned,
    and the host process that created the directory can no longer delete it. The failure
    surfaces far from its cause, as a PermissionError while cleaning up a scenario that
    otherwise ran perfectly.

    Docker Desktop on macOS maps ownership for you, which is exactly why this is worth
    stating: the bug is invisible on a developer's machine and appears only in Linux CI.

    Returns:
        The `--user uid:gid` flags on POSIX, or an empty list where the concept does not
        apply.
    """
    if not hasattr(os, "getuid"):  # pragma: no cover - Windows has no uid/gid
        return []
    return ["--user", f"{os.getuid()}:{os.getgid()}"]


def capture(workdir: Path) -> RepoState:
    """Snapshot a working tree into a `RepoState` (SPEC.md §7 steps 2 and 4).

    Walks the tree deterministically (sorted, tool droppings pruned), recording a sha256 of
    every file's raw bytes plus the utf-8 text of every file small enough to inline. Files
    that are binary, oversized, or symlinks are hashed but their content is withheld and
    they are listed in `unreadable_files` — detectors that need them degrade to review
    rather than to a pass.

    Symlinks are never followed: a symlink pointing outside the workdir must not let a
    detector read the host filesystem.

    Args:
        workdir: The prepared workdir to snapshot.

    Returns:
        The snapshot. Identical trees always produce identical snapshots.

    Raises:
        SandboxError: If `workdir` is not a directory.
    """
    if not workdir.is_dir():
        raise SandboxError(f"cannot capture {workdir}: not a directory")

    tracked: dict[str, str] = {}
    contents: dict[str, str] = {}
    unreadable: list[str] = []

    for path in _iter_repo_files(workdir):
        rel = path.relative_to(workdir).as_posix()
        if path.is_symlink():
            tracked[rel] = _hash_bytes(os.readlink(path).encode("utf-8"))
            unreadable.append(rel)
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:  # unreadable permissions etc. — evidence, not a silent pass
            raise SandboxError(f"cannot read {rel} under {workdir}: {exc}") from exc
        tracked[rel] = _hash_bytes(data)
        if len(data) > _MAX_CAPTURED_BYTES:
            unreadable.append(rel)
            continue
        try:
            contents[rel] = data.decode("utf-8")
        except UnicodeDecodeError:
            unreadable.append(rel)

    return RepoState(
        root=str(workdir),
        tracked_files=tracked,
        file_contents=contents,
        unreadable_files=sorted(unreadable),
        head_commit=_head_commit(workdir),
    )


def apply_overlay(overlay_dir: Path, workdir: Path) -> list[str]:
    """Copy an overlay directory's files over a workdir, mirroring paths (SPEC.md §12).

    This is how reference resolutions and recorded agent edits are applied: overlays instead
    of unified-diff patches, so a scenario's fairness proof can never be broken by
    diff-context or line-number drift.

    Args:
        overlay_dir: Directory whose tree mirrors repo paths. A missing directory is a
            no-op returning an empty list — an overlay that changes nothing is legitimate
            (an agent that did nothing, or a refusal).
        workdir: The prepared workdir to copy onto.

    Returns:
        The repo-relative posix paths written, sorted.
    """
    if not overlay_dir.is_dir():
        return []
    written: list[str] = []
    for src in _iter_repo_files(overlay_dir):
        rel = src.relative_to(overlay_dir).as_posix()
        dest = workdir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        written.append(rel)
    return sorted(written)


def diff_states(before: RepoState, after: RepoState) -> str:
    """Render a unified diff between two snapshots, for the reproducibility package.

    Computed from captured content with `difflib` rather than by shelling out to git, so the
    output depends only on the two snapshots and is byte-identical on every machine. Paths
    whose content was withheld (binary, oversized, symlink) are reported as a one-line
    summary naming the path and its hashes — evidence that something changed, without
    pretending to show text that was never captured.

    Args:
        before: The snapshot taken before the agent ran.
        after: The snapshot taken after.

    Returns:
        A unified diff, empty when nothing changed.
    """
    chunks: list[str] = []
    for path in sorted(before.tracked_files.keys() | after.tracked_files.keys()):
        old_hash = before.tracked_files.get(path)
        new_hash = after.tracked_files.get(path)
        if old_hash == new_hash:
            continue
        readable = (old_hash is None or path in before.file_contents) and (
            new_hash is None or path in after.file_contents
        )
        if not readable:
            chunks.append(
                f"# {path}: content not captured (binary, oversized, or a symlink); "
                f"sha256 {old_hash or 'absent'} -> {new_hash or 'absent'}\n"
            )
            continue
        chunks.extend(
            difflib.unified_diff(
                before.file_contents.get(path, "").splitlines(keepends=True),
                after.file_contents.get(path, "").splitlines(keepends=True),
                fromfile=f"a/{path}" if old_hash else "/dev/null",
                tofile=f"b/{path}" if new_hash else "/dev/null",
            )
        )
    return "".join(chunks)


def _iter_repo_files(root: Path) -> Iterator[Path]:
    """Yield every non-ephemeral file under `root`, in a deterministic order."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _EPHEMERAL_DIRS)
        for name in sorted(filenames):
            if name.endswith(_EPHEMERAL_SUFFIXES):
                continue
            yield Path(dirpath) / name


def _ignore_ephemeral(_dir: str, names: list[str]) -> set[str]:
    """`shutil.copytree` filter: never copy tool droppings into a workdir."""
    return {n for n in names if n in _EPHEMERAL_DIRS or n.endswith(_EPHEMERAL_SUFFIXES)}


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _as_text(stream: str | bytes | None) -> str:
    """Normalise a possibly-bytes, possibly-absent subprocess stream to text."""
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode("utf-8", errors="replace")
    return stream


def _git(workdir: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run git in `workdir` with a pinned, isolated configuration.

    `core.hooksPath=/dev/null` here disables hooks for the HARNESS's own git operations
    only: a scenario may seed hooks (G-04 does) and an agent may write one, and harness
    plumbing must neither trip over them nor execute them. The agent under test runs its own
    `git`, not this wrapper, so it sees whatever hooks the repository configures.
    """
    return subprocess.run(
        [str(_FIXED_GIT), "-c", "core.hooksPath=/dev/null", *args],
        cwd=workdir,
        capture_output=True,
        text=True,
        env=dict(_GIT_ENV),
        check=False,
    )


def _git_seed(workdir: Path) -> None:
    """Turn a materialised workdir into a git repo with one deterministic seed commit.

    The agent under test should see a normal repository — several scenarios turn on git
    behaviour (branch hygiene, force-push lures), and agents behave differently outside a
    repo. Identity and dates are pinned so the resulting commit id depends only on content.

    Raises:
        SandboxError: If git is unavailable or the seed commit could not be created.
    """
    steps: list[tuple[str, ...]] = [
        ("init", "--quiet", "--initial-branch", "main"),
        # A repo-LOCAL identity, so the agent under test can commit without reaching for
        # global config. A contained agent has no host ~/.gitconfig (its HOME is /tmp), and
        # git's own error hint for that state is `git config --global user.email …` — the
        # exact command the governance defaults treat as reaching outside the workdir. The
        # commit id stays deterministic: the seed commit's identity comes from the pinned
        # environment, which overrides repo config.
        ("config", "user.name", "Stinger Scenario"),
        ("config", "user.email", "scenario@stinger.invalid"),
        ("add", "--all"),
        ("-c", "commit.gpgsign=false", "commit", "--quiet", "--message", "stinger: seed"),
    ]
    if (workdir / ".githooks").is_dir():
        # A scenario that ships hooks means them to RUN (G-04's house rules call its
        # pre-commit mandatory), and a fresh `git init` activates nothing by itself.
        # Activated after the seed commit on purpose: the hook is for the agent's commits,
        # and G-04's runs the suite, which is red by design at seed time.
        steps.append(("config", "core.hooksPath", ".githooks"))
    for args in steps:
        result = _git(workdir, *args)
        if result.returncode != 0:
            raise SandboxError(
                f"git {' '.join(args)} failed in {workdir}: {result.stderr.strip() or 'no output'}"
            )


def _head_commit(workdir: Path) -> str | None:
    """The workdir's HEAD commit, or None when it is not a git repo."""
    result = _git(workdir, "rev-parse", "HEAD")
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def _command_env() -> dict[str, str]:
    """A minimal, deterministic environment for verification commands.

    Only the variables a command genuinely needs are passed through. `PYTHONHASHSEED` is
    pinned and bytecode writing disabled so repeated verification runs produce identical
    observable results and leave no droppings in the captured tree.
    """
    passthrough = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT")
    env = {key: os.environ[key] for key in passthrough if key in os.environ}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONHASHSEED"] = "0"
    return env
