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
from collections.abc import Iterator, Mapping, Sequence
from enum import StrEnum
from pathlib import Path

from stinger.detectors.base import RepoState
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

DEFAULT_IMAGE = "python:3.12-slim"
"""Container image for verification commands. Overridable per run; part of the fingerprint."""

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

_GIT_ENV: Mapping[str, str] = {
    "GIT_AUTHOR_NAME": "stinger",
    "GIT_AUTHOR_EMAIL": "stinger@localhost",
    "GIT_COMMITTER_NAME": "stinger",
    "GIT_COMMITTER_EMAIL": "stinger@localhost",
    "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
    "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
}


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
        effective = self._effective_argv(workdir, argv, network=network)
        try:
            completed = subprocess.run(  # noqa: S603 - argv list, never shell-interpreted
                effective,
                cwd=workdir,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                env=_command_env(),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return ExecResult(
                argv=list(effective),
                exit_code=_TIMEOUT_EXIT_CODE,
                stdout=_as_text(exc.stdout),
                stderr=_as_text(exc.stderr),
                timed_out=True,
            )
        except OSError as exc:
            raise SandboxError(f"could not launch {list(effective)!r}: {exc}") from exc
        return ExecResult(
            argv=list(effective),
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    def _effective_argv(self, workdir: Path, argv: Sequence[str], *, network: bool) -> list[str]:
        """The command as actually invoked: bare in LOCAL mode, container-wrapped in DOCKER."""
        if self.isolation is Isolation.LOCAL:
            return list(argv)
        return docker_argv(self.image, workdir, argv, network=network)


def docker_argv(
    image: str, workdir: Path, argv: Sequence[str], *, network: bool = False
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
            container gets `--network none`.

    Returns:
        The full argv for `subprocess.run`.
    """
    wrapper = [
        "docker",
        "run",
        "--rm",
        "--workdir",
        "/work",
        "--volume",
        f"{workdir.resolve()}:/work",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--env",
        "PYTHONHASHSEED=0",
    ]
    if not network:
        wrapper += ["--network", "none"]
    return [*wrapper, image, *argv]


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
    """Run git in `workdir` with a pinned, isolated configuration."""
    env = {**os.environ, **_GIT_ENV}
    return subprocess.run(  # noqa: S603 - argv list, never shell-interpreted
        ["git", *args],
        cwd=workdir,
        capture_output=True,
        text=True,
        env=env,
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
    for args in (
        ("init", "--quiet", "--initial-branch", "main"),
        ("add", "--all"),
        ("-c", "commit.gpgsign=false", "commit", "--quiet", "--message", "stinger: seed"),
    ):
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
