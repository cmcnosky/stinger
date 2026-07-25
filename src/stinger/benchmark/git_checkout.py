"""Fixed-binary, ambient-environment-resistant Git checkout verification.

Release evidence must not inherit ``PATH`` or ``GIT_*`` variables from the process that
invoked Stinger.  Otherwise a shim executable or an alternate ``GIT_DIR`` can make a dirty
checkout appear clean.  This module centralizes the narrow, read-only Git boundary used by
benchmark evidence builders.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

_FIXED_GIT: Final = Path("/usr/bin/git")
_COMMIT_PATTERN: Final = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_DEFAULT_TIMEOUT_SECONDS: Final = 120
_READ_CHUNK: Final = 1024 * 1024
_SANITIZED_GIT_ENV: Final = {
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
_FIXED_CONFIG: Final = (
    "-c",
    "core.attributesFile=/dev/null",
    "-c",
    "core.excludesFile=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.ignoreStat=false",
)
STINGER_IMPLEMENTATION_ROOTS: Final = (
    "src/stinger",
    "scripts",
    "docker",
    "benchmark/protocol.yaml",
)


class GitCheckoutError(Exception):
    """Raised when an exact checkout identity cannot be established safely."""


class DirtyGitCheckoutError(GitCheckoutError):
    """Raised when a real checkout is observable but not clean at exact ``HEAD``."""


@dataclass(frozen=True, slots=True)
class TrackedImplementationFile:
    """One committed regular file verified against exact working-tree bytes."""

    relative_path: str
    mode: str
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedTrackedImplementation:
    """Complete verified inventory for a caller-selected set of tracked roots."""

    commit: str
    files: tuple[TrackedImplementationFile, ...]
    inventory_sha256: str


@dataclass(frozen=True, slots=True)
class _GitContext:
    """Resolved real worktree and Git metadata directory."""

    root: Path
    git_dir: Path


def clean_exact_git_head(repository: Path, *, timeout: int = _DEFAULT_TIMEOUT_SECONDS) -> str:
    """Return ``HEAD`` only for a real checkout with no tracked or untracked changes."""
    context = _git_context(repository, timeout=timeout)
    return _clean_exact_git_head(context, timeout=timeout)


def verify_tracked_implementation(
    repository: Path,
    *,
    expected_commit: str,
    tracked_roots: tuple[str, ...],
    timeout: int = _DEFAULT_TIMEOUT_SECONDS,
) -> VerifiedTrackedImplementation:
    """Verify every committed regular file under ``tracked_roots`` against disk.

    The returned inventory is a convenience commitment.  The Git commit remains the
    authoritative content-addressed identity; this function additionally proves that the
    selected implementation roots in the supplied worktree contain those exact bytes.
    """
    if _COMMIT_PATTERN.fullmatch(expected_commit) is None:
        raise GitCheckoutError("expected Git commit is not an exact object id")
    if not tracked_roots or any(not _canonical_tracked_root(root) for root in tracked_roots):
        raise GitCheckoutError("tracked implementation roots are invalid")

    context = _git_context(repository, timeout=timeout)
    if _clean_exact_git_head(context, timeout=timeout) != expected_commit:
        raise GitCheckoutError("checkout does not match the expected commit")
    listing = _run_fixed_git(
        context,
        (
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            expected_commit,
            "--",
            *tracked_roots,
        ),
        timeout=timeout,
    )
    if listing.returncode != 0 or not listing.stdout:
        raise GitCheckoutError("tracked implementation inventory is unavailable")

    verified: list[TrackedImplementationFile] = []
    for raw_entry in listing.stdout.split(b"\0"):
        if not raw_entry:
            continue
        try:
            raw_metadata, raw_path = raw_entry.split(b"\t", 1)
            mode, object_type, object_id = raw_metadata.decode("ascii").split(" ", 2)
            relative_text = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            raise GitCheckoutError("tracked implementation inventory is malformed") from None
        relative = PurePosixPath(relative_text)
        if (
            object_type != "blob"
            or mode not in {"100644", "100755"}
            or not _canonical_relative_path(relative)
            or not any(
                relative == PurePosixPath(root) or relative.is_relative_to(PurePosixPath(root))
                for root in tracked_roots
            )
        ):
            raise GitCheckoutError("tracked implementation contains an unsupported node")

        working_path = context.root.joinpath(*relative.parts)
        content = _read_regular_nonsymlink(working_path)
        try:
            resolved = working_path.resolve(strict=True)
            resolved.relative_to(context.root)
        except (OSError, ValueError):
            raise GitCheckoutError("tracked implementation escapes the checkout") from None
        committed = _run_fixed_git(
            context,
            ("cat-file", "blob", object_id),
            timeout=timeout,
        )
        if committed.returncode != 0 or committed.stdout != content:
            raise GitCheckoutError("tracked implementation differs from committed bytes")
        verified.append(
            TrackedImplementationFile(
                relative_path=relative_text,
                mode=mode,
                sha256=hashlib.sha256(content).hexdigest(),
            )
        )

    if not verified:
        raise GitCheckoutError("tracked implementation inventory is empty")
    files = tuple(sorted(verified, key=lambda item: item.relative_path))
    payload = json.dumps(
        {
            "commit": expected_commit,
            "files": [
                {
                    "mode": item.mode,
                    "path": item.relative_path,
                    "sha256": item.sha256,
                }
                for item in files
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return VerifiedTrackedImplementation(
        commit=expected_commit,
        files=files,
        inventory_sha256=hashlib.sha256(payload).hexdigest(),
    )


def verify_loaded_stinger_implementation(
    repository: Path,
    *,
    expected_commit: str,
    timeout: int = _DEFAULT_TIMEOUT_SECONDS,
) -> VerifiedTrackedImplementation:
    """Bind all loaded Stinger modules and complete implementation roots to one commit.

    A caller-supplied clean checkout is not evidence that the executing Python modules came
    from that checkout. This verifier inventories every implementation root that can affect
    a benchmark workflow, then requires every loaded ``stinger`` module to resolve inside
    that exact source tree and match the committed bytes. A final clean-head observation
    closes changes made while module bytes were being checked.
    """
    verified = verify_tracked_implementation(
        repository,
        expected_commit=expected_commit,
        tracked_roots=STINGER_IMPLEMENTATION_ROOTS,
        timeout=timeout,
    )
    try:
        root = repository.resolve(strict=True)
        source_root = (root / "src" / "stinger").resolve(strict=True)
    except OSError:
        raise GitCheckoutError("loaded Stinger checkout is unavailable") from None
    inventory = {item.relative_path: item.sha256 for item in verified.files}

    for module_name, module in tuple(sys.modules.items()):
        if module_name != "stinger" and not module_name.startswith("stinger."):
            continue
        source_value = getattr(module, "__file__", None)
        if not isinstance(source_value, str) or not source_value:
            raise GitCheckoutError("loaded Stinger module source is unavailable")
        source_path = Path(source_value)
        if source_path.suffix in {".pyc", ".pyo"}:
            try:
                source_path = Path(importlib.util.source_from_cache(str(source_path)))
            except ValueError:
                raise GitCheckoutError("loaded Stinger module source is unavailable") from None
        try:
            source = source_path.resolve(strict=True)
            source.relative_to(source_root)
            relative = source.relative_to(root).as_posix()
        except (OSError, ValueError):
            raise GitCheckoutError(
                "loaded Stinger module is outside the supplied checkout"
            ) from None
        expected_sha256 = inventory.get(relative)
        if expected_sha256 is None:
            raise GitCheckoutError(
                "loaded Stinger module is not bound to the tracked implementation"
            )
        if hashlib.sha256(_read_regular_nonsymlink(source)).hexdigest() != expected_sha256:
            raise GitCheckoutError("loaded Stinger module differs from committed checkout bytes")

    if clean_exact_git_head(root, timeout=timeout) != expected_commit:
        raise GitCheckoutError("loaded Stinger implementation changed during verification")
    return verified


def _git_context(repository: Path, *, timeout: int) -> _GitContext:
    """Resolve one real worktree without consulting ambient Git routing variables."""
    _require_fixed_git()
    try:
        metadata = repository.lstat()
        root = repository.resolve(strict=True)
    except OSError:
        raise GitCheckoutError("Git checkout is unavailable") from None
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise GitCheckoutError("Git checkout is not a real directory")
    marker = root / ".git"
    try:
        marker_metadata = marker.lstat()
    except OSError:
        raise GitCheckoutError("Git checkout metadata is unavailable") from None
    if stat.S_ISLNK(marker_metadata.st_mode) or not (
        stat.S_ISDIR(marker_metadata.st_mode) or stat.S_ISREG(marker_metadata.st_mode)
    ):
        raise GitCheckoutError("Git checkout metadata is not a real Git marker")

    try:
        discovered = subprocess.run(
            (
                str(_FIXED_GIT),
                "-C",
                str(root),
                *_FIXED_CONFIG,
                "rev-parse",
                "--absolute-git-dir",
            ),
            env=dict(_SANITIZED_GIT_ENV),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise GitCheckoutError("Git checkout metadata could not be resolved") from None
    try:
        raw_git_dir = discovered.stdout.decode("utf-8").strip()
        candidate = Path(raw_git_dir)
        git_dir_metadata = candidate.lstat()
        git_dir = candidate.resolve(strict=True)
    except (OSError, UnicodeDecodeError):
        raise GitCheckoutError("Git checkout metadata could not be resolved") from None
    if (
        discovered.returncode != 0
        or not raw_git_dir
        or not candidate.is_absolute()
        or stat.S_ISLNK(git_dir_metadata.st_mode)
        or not stat.S_ISDIR(git_dir_metadata.st_mode)
    ):
        raise GitCheckoutError("Git checkout metadata could not be resolved")
    return _GitContext(root=root, git_dir=git_dir)


def _clean_exact_git_head(context: _GitContext, *, timeout: int) -> str:
    """Return exact clean ``HEAD`` using an already resolved fixed Git context."""
    head = _run_fixed_git(
        context,
        ("rev-parse", "--verify", "HEAD^{commit}"),
        timeout=timeout,
    )
    status = _run_fixed_git(
        context,
        (
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ),
        timeout=timeout,
    )
    try:
        commit = head.stdout.decode("ascii").strip()
    except UnicodeDecodeError:
        raise GitCheckoutError("Git checkout identity is not canonical") from None
    if (
        head.returncode != 0
        or status.returncode != 0
        or status.stdout
        or _COMMIT_PATTERN.fullmatch(commit) is None
    ):
        raise DirtyGitCheckoutError("Git checkout is not clean at an exact commit")
    return commit


def _run_fixed_git(
    context: _GitContext,
    arguments: tuple[str, ...],
    *,
    timeout: int,
) -> subprocess.CompletedProcess[bytes]:
    """Run a bounded fixed Git command with explicit worktree routing and clean env."""
    try:
        return subprocess.run(
            (
                str(_FIXED_GIT),
                "--git-dir",
                str(context.git_dir),
                "--work-tree",
                str(context.root),
                *_FIXED_CONFIG,
                *arguments,
            ),
            cwd=context.root,
            env=dict(_SANITIZED_GIT_ENV),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise GitCheckoutError("fixed Git command failed") from None


def _require_fixed_git() -> None:
    """Require the platform-fixed client path to be a regular executable."""
    try:
        metadata = _FIXED_GIT.stat()
    except OSError:
        raise GitCheckoutError("fixed Git executable is unavailable") from None
    if not stat.S_ISREG(metadata.st_mode) or not os.access(_FIXED_GIT, os.X_OK):
        raise GitCheckoutError("fixed Git executable is unavailable")


def _read_regular_nonsymlink(path: Path) -> bytes:
    """Read exact regular-file bytes without following the final path component."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise GitCheckoutError("tracked implementation file is unavailable") from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise GitCheckoutError("tracked implementation file is not regular")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, _READ_CHUNK)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def _canonical_tracked_root(value: str) -> bool:
    """Return whether one tracked-root selector is canonical and repository-relative."""
    if not value or "\\" in value:
        return False
    return _canonical_relative_path(PurePosixPath(value))


def _canonical_relative_path(path: PurePosixPath) -> bool:
    """Return whether a POSIX path is nonempty, relative, and traversal-free."""
    return (
        bool(path.parts)
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


__all__ = [
    "DirtyGitCheckoutError",
    "GitCheckoutError",
    "TrackedImplementationFile",
    "VerifiedTrackedImplementation",
    "clean_exact_git_head",
    "verify_tracked_implementation",
]
