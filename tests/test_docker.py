"""The Docker isolation path, exercised against a real daemon (SPEC.md §2).

Everything here is skipped when Docker is unavailable, because a developer without a running
daemon should still get a green gate — the *contract* (argv shape, `--network none`, the
mount) is asserted unconditionally in test_sandbox.py, and that is what CI relies on.

These tests exist because argv assertions cannot catch the class of bug that actually bit:
`python:3.12-slim` has no pytest, so under Docker every completion check failed for a reason
unrelated to the agent, and every scenario would have scored as a failure. The argv was
perfect. Only running it showed the problem.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from stinger.harness.sandbox import (
    DEFAULT_IMAGE,
    Isolation,
    Sandbox,
    SandboxError,
    apply_overlay,
)
from stinger.scenario.manifest import ScenarioManifest, validate_scenario


def _docker_ready() -> bool:
    """Whether a daemon is reachable AND Stinger's verification image is built."""
    if shutil.which("docker") is None:
        return False
    probe = subprocess.run(
        ["docker", "image", "inspect", DEFAULT_IMAGE],
        capture_output=True,
        check=False,
    )
    return probe.returncode == 0


pytestmark = pytest.mark.skipif(
    not _docker_ready(),
    reason=(
        f"needs a running Docker daemon and the {DEFAULT_IMAGE} image "
        f"(docker build -t {DEFAULT_IMAGE} -f docker/runner.Dockerfile .)"
    ),
)


@pytest.fixture
def box() -> Sandbox:
    return Sandbox(isolation=Isolation.DOCKER)


class TestPreflight:
    """A run must not start against an image that cannot serve a completion check."""

    def test_the_shipped_image_passes(self, box: Sandbox) -> None:
        box.preflight()  # must not raise

    def test_an_image_without_pytest_is_refused_with_a_remedy(self) -> None:
        """THE bug this whole module exists for: it would have zeroed every score silently."""
        bare = Sandbox(isolation=Isolation.DOCKER, image="python:3.12-slim")

        with pytest.raises(SandboxError) as caught:
            bare.preflight()

        message = str(caught.value)
        assert "could not import pytest" in message
        assert "docker build" in message  # the message says exactly how to fix it
        assert DEFAULT_IMAGE in message

    def test_a_missing_image_is_refused(self) -> None:
        missing = Sandbox(isolation=Isolation.DOCKER, image="stinger-no-such-image:0")

        with pytest.raises(SandboxError, match="not usable"):
            missing.preflight()

    def test_local_isolation_needs_no_preflight(self) -> None:
        Sandbox(isolation=Isolation.LOCAL).preflight()  # must not raise


class TestVerificationInsideAContainer:
    def test_the_completion_check_discriminates_inside_a_container(
        self, box: Sandbox, t02_dir: Path, t02: ScenarioManifest, tmp_path: Path
    ) -> None:
        """Fails on the seeded bug, passes on the honest fix — the whole point of the check."""
        workdir = box.prepare(t02_dir, t02, tmp_path / "wd")
        check = ["python", "-m", "pytest", "-q", "tests/"]

        assert not box.run_command(workdir, check, 300).ok

        apply_overlay(t02_dir / t02.reference_honest, workdir)
        assert box.run_command(workdir, check, 300).ok

    def test_the_container_really_has_no_network(
        self, box: Sandbox, t02_dir: Path, t02: ScenarioManifest, tmp_path: Path
    ) -> None:
        """SPEC §2: nothing whose result feeds scoring may reach the network."""
        workdir = box.prepare(t02_dir, t02, tmp_path / "wd")

        result = box.run_command(
            workdir,
            ["python", "-c", "import socket; socket.create_connection(('1.1.1.1', 53), timeout=3)"],
            60,
        )

        assert not result.ok

    def test_the_container_sees_only_the_workdir(
        self, box: Sandbox, t02_dir: Path, t02: ScenarioManifest, tmp_path: Path
    ) -> None:
        """The mount is the isolation; a scenario must not be able to read the corpus."""
        workdir = box.prepare(t02_dir, t02, tmp_path / "wd")

        listing = box.run_command(workdir, ["ls", "/work"], 60)
        outside = box.run_command(workdir, ["ls", str(t02_dir)], 60)

        assert "src" in listing.stdout
        assert not outside.ok  # the scenario's reference answers are not reachable


class TestTheValidityContractUnderDocker:
    def test_t02_validates_in_real_containers(self, t02_dir: Path, t02: ScenarioManifest) -> None:
        """The same contract that runs under --local, run for real (SPEC §12)."""
        validate_scenario(t02_dir, t02, sandbox=Sandbox(isolation=Isolation.DOCKER))
