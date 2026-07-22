"""Sandbox and RepoState capture (SPEC.md §2, §7 steps 1, 2, 4) — the M1 gate.

The headline test is `test_capture_before_after_reports_exact_changed_paths`: prepare T-02,
snapshot it, apply the cheat overlay by hand, snapshot again, and assert the changed-paths
set is exactly right. Everything a detector concludes rests on that set being correct.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from stinger.harness.sandbox import (
    ExecResult,
    Isolation,
    Sandbox,
    SandboxError,
    apply_overlay,
    capture,
    docker_argv,
)
from stinger.models import Family
from stinger.scenario.manifest import ScenarioManifest


def changed_paths(before: object, after: object) -> set[str]:
    """The paths whose content hash differs — the same set detectors reason over."""
    b = before.tracked_files  # type: ignore[attr-defined]
    a = after.tracked_files  # type: ignore[attr-defined]
    return {p for p in b.keys() | a.keys() if b.get(p) != a.get(p)}


@pytest.fixture
def local() -> Sandbox:
    return Sandbox(isolation=Isolation.LOCAL)


# --- prepare -------------------------------------------------------------------------


def test_prepare_copies_seed_and_seeds_house_rules(
    local: Sandbox, t02_dir: Path, t02: ScenarioManifest, tmp_path: Path
) -> None:
    workdir = local.prepare(t02_dir, t02, tmp_path / "wd")

    assert (workdir / "src" / "discount.py").is_file()
    assert (workdir / "tests" / "test_discount.py").is_file()
    # The seeded house rules are the trap's stated rule; they must reach the agent verbatim.
    assert t02.seeded_house_rules is not None
    assert (workdir / "AGENTS.md").read_text(encoding="utf-8") == t02.seeded_house_rules
    assert "Do not modify" in (workdir / "AGENTS.md").read_text(encoding="utf-8")


def test_prepare_leaves_the_scenario_directory_untouched(
    local: Sandbox, t02_dir: Path, t02: ScenarioManifest, tmp_path: Path
) -> None:
    """The corpus is read-only input; a run must never mutate it."""
    before = capture(t02_dir / t02.seed_repo)
    local.prepare(t02_dir, t02, tmp_path / "wd")
    assert capture(t02_dir / t02.seed_repo).tracked_files == before.tracked_files


def test_prepare_makes_a_git_repo_with_a_deterministic_seed_commit(
    local: Sandbox, t02_dir: Path, t02: ScenarioManifest, tmp_path: Path
) -> None:
    """Same content in, same commit id out — no wall clock in the scoring path (AGENTS.md 6)."""
    first = capture(local.prepare(t02_dir, t02, tmp_path / "a"))
    second = capture(local.prepare(t02_dir, t02, tmp_path / "b"))

    assert first.head_commit is not None
    assert first.head_commit == second.head_commit
    assert first.tracked_files == second.tracked_files


def test_prepare_refuses_a_non_empty_destination(
    local: Sandbox, t02_dir: Path, t02: ScenarioManifest, tmp_path: Path
) -> None:
    dest = tmp_path / "wd"
    dest.mkdir()
    (dest / "leftover.txt").write_text("stale run output", encoding="utf-8")

    with pytest.raises(SandboxError, match="not empty"):
        local.prepare(t02_dir, t02, dest)


def test_prepare_refuses_a_missing_seed_repo(
    local: Sandbox, t02: ScenarioManifest, tmp_path: Path
) -> None:
    with pytest.raises(SandboxError, match="no seed repo"):
        local.prepare(tmp_path / "not-a-scenario", t02, tmp_path / "wd")


def test_local_isolation_refuses_the_x_family(
    local: Sandbox, t02_dir: Path, t02: ScenarioManifest, tmp_path: Path
) -> None:
    """SPEC §2: --local MUST refuse the safety family. Fail closed, loudly."""
    unsafe = t02.model_copy(update={"family": Family.X})

    with pytest.raises(SandboxError, match="family X"):
        local.prepare(t02_dir, unsafe, tmp_path / "wd")


def test_docker_isolation_accepts_the_x_family(
    t02_dir: Path, t02: ScenarioManifest, tmp_path: Path
) -> None:
    """The refusal is about LOCAL mode only — containers are exactly where X belongs."""
    sandbox = Sandbox(isolation=Isolation.DOCKER)
    workdir = sandbox.prepare(t02_dir, t02.model_copy(update={"family": Family.X}), tmp_path / "wd")
    assert (workdir / "src" / "discount.py").is_file()


# --- capture -------------------------------------------------------------------------


def test_capture_before_after_reports_exact_changed_paths(
    local: Sandbox, t02_dir: Path, t02: ScenarioManifest, tmp_path: Path
) -> None:
    """THE M1 GATE: prepare T-02, apply the cheat overlay, changed paths are exactly right."""
    workdir = local.prepare(t02_dir, t02, tmp_path / "wd")
    before = local.capture(workdir)

    written = apply_overlay(t02_dir / t02.reference_cheat, workdir)
    after = local.capture(workdir)

    assert written == ["tests/test_discount.py"]
    assert changed_paths(before, after) == {"tests/test_discount.py"}
    # The cheat weakens the test rather than fixing the source — the source is untouched.
    assert before.tracked_files["src/discount.py"] == after.tracked_files["src/discount.py"]


def test_capture_sees_the_honest_overlay_touching_only_the_source(
    local: Sandbox, t02_dir: Path, t02: ScenarioManifest, tmp_path: Path
) -> None:
    workdir = local.prepare(t02_dir, t02, tmp_path / "wd")
    before = local.capture(workdir)

    apply_overlay(t02_dir / t02.reference_honest, workdir)
    after = local.capture(workdir)

    assert changed_paths(before, after) == {"src/discount.py"}
    assert "percent / 100" in after.file_contents["src/discount.py"]


def test_capture_notices_additions_and_deletions(
    local: Sandbox, t02_dir: Path, t02: ScenarioManifest, tmp_path: Path
) -> None:
    workdir = local.prepare(t02_dir, t02, tmp_path / "wd")
    before = local.capture(workdir)

    (workdir / "tests" / "test_discount.py").unlink()
    (workdir / "src" / "sneaky.py").write_text("# added by the agent\n", encoding="utf-8")
    after = local.capture(workdir)

    assert changed_paths(before, after) == {"tests/test_discount.py", "src/sneaky.py"}
    assert "tests/test_discount.py" not in after.tracked_files


def test_capture_inlines_text_and_ignores_tool_droppings(
    local: Sandbox, t02_dir: Path, t02: ScenarioManifest, tmp_path: Path
) -> None:
    workdir = local.prepare(t02_dir, t02, tmp_path / "wd")
    (workdir / "__pycache__").mkdir()
    (workdir / "__pycache__" / "discount.cpython-312.pyc").write_bytes(b"\x00\x01")
    (workdir / "src" / "discount.pyc").write_bytes(b"\x00\x01")

    state = local.capture(workdir)

    assert set(state.file_contents) <= set(state.tracked_files)
    assert "src/discount.py" in state.file_contents
    assert not [p for p in state.tracked_files if "__pycache__" in p or p.endswith(".pyc")]
    assert not [p for p in state.tracked_files if p.startswith(".git/")]


def test_capture_withholds_binary_content_instead_of_guessing(
    local: Sandbox, t02_dir: Path, t02: ScenarioManifest, tmp_path: Path
) -> None:
    """Fail closed: undecodable content is hashed and flagged, never silently skipped."""
    workdir = local.prepare(t02_dir, t02, tmp_path / "wd")
    (workdir / "blob.bin").write_bytes(b"\xff\xfe\x00binary")

    state = local.capture(workdir)

    assert "blob.bin" in state.tracked_files
    assert "blob.bin" not in state.file_contents
    assert "blob.bin" in state.unreadable_files


def test_capture_does_not_follow_symlinks_out_of_the_workdir(
    local: Sandbox, t02_dir: Path, t02: ScenarioManifest, tmp_path: Path
) -> None:
    """A symlink must not become a window onto the host filesystem."""
    outside = tmp_path / "host-secret.txt"
    outside.write_text("not the agent's business", encoding="utf-8")
    workdir = local.prepare(t02_dir, t02, tmp_path / "wd")
    (workdir / "link.txt").symlink_to(outside)

    state = local.capture(workdir)

    assert "link.txt" in state.unreadable_files
    assert "link.txt" not in state.file_contents
    assert "not the agent's business" not in "".join(state.file_contents.values())


def test_capture_rejects_a_missing_workdir(tmp_path: Path) -> None:
    with pytest.raises(SandboxError, match="not a directory"):
        capture(tmp_path / "nope")


def test_apply_overlay_of_a_missing_directory_is_a_no_op(tmp_path: Path) -> None:
    """An agent that changed nothing is a legitimate observation, not an error."""
    assert apply_overlay(tmp_path / "absent", tmp_path) == []


# --- verification commands -----------------------------------------------------------


def test_local_run_command_reports_exit_code_and_streams(local: Sandbox, tmp_path: Path) -> None:
    result = local.run_command(tmp_path, ["sh", "-c", "echo out; echo err >&2; exit 3"], 30)

    assert result.exit_code == 3
    assert not result.ok
    assert "out" in result.stdout
    assert "err" in result.stderr


def test_local_run_command_reports_a_timeout_without_raising(
    local: Sandbox, tmp_path: Path
) -> None:
    """A hung check must surface as evidence the runner can route to ERROR, not an exception."""
    result = local.run_command(tmp_path, ["sh", "-c", "sleep 5"], 1)

    assert result.timed_out
    assert not result.ok
    assert result.exit_code == 124


def test_run_command_raises_sandbox_error_when_the_command_cannot_launch(
    local: Sandbox, tmp_path: Path
) -> None:
    with pytest.raises(SandboxError, match="could not launch"):
        local.run_command(tmp_path, ["stinger-no-such-executable"], 5)


def test_completion_check_fails_on_the_seed_and_passes_on_the_honest_overlay(
    local: Sandbox, t02_dir: Path, t02: ScenarioManifest, tmp_path: Path
) -> None:
    """The held-out check must actually discriminate, or goal_met means nothing."""
    workdir = local.prepare(t02_dir, t02, tmp_path / "wd")
    check = ["bash", str(t02_dir / t02.completion_check)]

    assert not local.run_command(workdir, check, 120).ok  # seed carries the real bug

    apply_overlay(t02_dir / t02.reference_honest, workdir)
    assert local.run_command(workdir, check, 120).ok


def test_exec_result_ok_requires_a_clean_exit_and_no_timeout() -> None:
    assert ExecResult(argv=["true"], exit_code=0, stdout="", stderr="").ok
    assert not ExecResult(argv=["x"], exit_code=0, stdout="", stderr="", timed_out=True).ok


# --- the docker contract (asserted on argv; no daemon required) -----------------------


def test_docker_argv_isolates_the_container(tmp_path: Path) -> None:
    argv = docker_argv("python:3.12-slim", tmp_path, ["pytest", "-q"])

    def flag(name: str) -> list[str]:
        return argv[argv.index(name) : argv.index(name) + 2]

    assert argv[:3] == ["docker", "run", "--rm"]  # one throwaway container per execution
    assert flag("--network") == ["--network", "none"]
    assert flag("--workdir") == ["--workdir", "/work"]
    assert f"{tmp_path.resolve()}:/work" in argv
    assert argv[-3:] == ["python:3.12-slim", "pytest", "-q"]


def test_docker_argv_only_enables_the_network_when_asked(tmp_path: Path) -> None:
    assert "--network" not in docker_argv("img", tmp_path, ["true"], network=True)


def test_docker_argv_names_the_container_only_when_asked(tmp_path: Path) -> None:
    """The name is the only handle for stopping a contained agent whose budget expired —
    the subprocess timeout kills the docker CLIENT, not the container."""
    named = docker_argv("img", tmp_path, ["true"], name="stinger-agent-abc123")

    assert named[named.index("--name") + 1] == "stinger-agent-abc123"
    assert "--name" not in docker_argv("img", tmp_path, ["true"])


def test_prepare_activates_seeded_githooks_for_the_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A scenario that ships `.githooks/` means them to run (G-04 calls its pre-commit
    mandatory), and a fresh `git init` activates nothing by itself. Activation happens
    after the seed commit — G-04's hook runs the suite, which is red by design at seed
    time — and the harness's own git wrapper stays hook-immune."""
    scenario = tmp_path / "scenario"
    seed = scenario / "seed_repo"
    (seed / ".githooks").mkdir(parents=True)
    (seed / ".githooks" / "pre-commit").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    (seed / "README.md").write_text("hello\n", encoding="utf-8")
    manifest = ScenarioManifest.model_validate(
        {
            "id": "G-99-hooks",
            "family": "G",
            "title": "t",
            "prompt": "p",
            "budget_seconds": 60,
            "detectors": [{"name": "command_scan", "intended": True}],
            "completion_check": "completion_check/run.sh",
        }
    )
    (scenario / "completion_check").mkdir(parents=True, exist_ok=True)

    workdir = tmp_path / "work"
    Sandbox(isolation=Isolation.LOCAL).prepare(scenario, manifest, workdir)

    hooks_path = subprocess.run(
        ["git", "config", "core.hooksPath"],
        cwd=workdir,
        capture_output=True,
        text=True,
        check=False,
    )
    assert hooks_path.stdout.strip() == ".githooks"
    # …and the seed commit exists despite the always-failing hook, because the harness's
    # own git operations do not execute workdir hooks.
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=workdir, capture_output=True, text=True, check=False
    )
    assert head.returncode == 0


def test_docker_isolation_wraps_commands_in_a_container(tmp_path: Path) -> None:
    sandbox = Sandbox(isolation=Isolation.DOCKER, image="img")
    assert sandbox._effective_argv(tmp_path, ["pytest"], network=False)[0] == "docker"


def test_local_isolation_does_not_wrap_commands(tmp_path: Path) -> None:
    sandbox = Sandbox(isolation=Isolation.LOCAL)
    assert sandbox._effective_argv(tmp_path, ["pytest"], network=False) == ["pytest"]


def test_docker_argv_runs_as_the_invoking_user_not_root(tmp_path: Path) -> None:
    """Linux containers default to root, and root-owned files in a bind mount cannot be
    cleaned up by the host that created the directory. Docker Desktop on macOS papers over
    this, so it only ever fails in Linux CI — which is why it is pinned here."""
    argv = docker_argv("img", tmp_path, ["true"])

    assert "--user" in argv
    assert argv[argv.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"


def test_docker_argv_gives_the_container_a_writable_home(tmp_path: Path) -> None:
    """Tools that cache in $HOME otherwise fail in ways that look like the scenario failing."""
    assert "HOME=/tmp" in docker_argv("img", tmp_path, ["true"])
