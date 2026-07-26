"""The Docker isolation path, exercised against a real daemon (SPEC.md §2).

Everything here is skipped when Docker is unavailable for an ordinary developer run. CI sets
``STINGER_REQUIRE_REAL_DOCKER_TESTS=1`` so a missing daemon or fixture image fails instead of
silently reducing the real-container coverage.

These tests exist because argv assertions cannot catch the class of bug that actually bit:
`python:3.12-slim` has no pytest, so under Docker every completion check failed for a reason
unrelated to the agent, and every scenario would have scored as a failure. The argv was
perfect. Only running it showed the problem.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Iterator
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

REPOSITORY = Path(__file__).resolve().parents[1]
REQUIRE_REAL_DOCKER_TESTS_ENV = "STINGER_REQUIRE_REAL_DOCKER_TESTS"


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


@pytest.fixture(scope="module", autouse=True)
def require_real_docker_fixture() -> None:
    """Fail under the mandatory CI policy and skip only optional local Docker runs."""
    if _docker_ready():
        return
    message = (
        f"needs a running Docker daemon and the {DEFAULT_IMAGE} image "
        "(build it with README.md's deterministic platform-specific recipe)"
    )
    if os.environ.get(REQUIRE_REAL_DOCKER_TESTS_ENV) == "1":
        pytest.fail(f"{message}; {REQUIRE_REAL_DOCKER_TESTS_ENV}=1")
    pytest.skip(message)


@pytest.fixture
def box() -> Sandbox:
    sandbox = Sandbox(isolation=Isolation.DOCKER)
    sandbox.preflight()
    return sandbox


@pytest.fixture(scope="module")
def image_without_pytest() -> Iterator[str]:
    """Create a network-disabled, local-only negative fixture from the approved image.

    The test must not assume that a mutable public base-image tag already exists in the
    daemon's image store. Container-backed Buildx intentionally keeps its build cache
    separate from that store, so the old assumption made CI depend on unrelated cache state.
    """
    suffix = str(os.getpid())
    container_name = f"stinger-test-no-pytest-{suffix}"
    image_name = f"stinger-test-no-pytest:{suffix}"
    try:
        subprocess.run(
            [
                "docker",
                "run",
                "--name",
                container_name,
                "--network",
                "none",
                DEFAULT_IMAGE,
                "python",
                "-m",
                "pip",
                "uninstall",
                "--yes",
                "pytest",
            ],
            capture_output=True,
            check=True,
            text=True,
        )
        subprocess.run(
            ["docker", "commit", container_name, image_name],
            capture_output=True,
            check=True,
            text=True,
        )
        yield image_name
    finally:
        subprocess.run(
            ["docker", "rm", "--force", container_name],
            capture_output=True,
            check=False,
            text=True,
        )
        subprocess.run(
            ["docker", "image", "rm", "--force", image_name],
            capture_output=True,
            check=False,
            text=True,
        )


class TestPreflight:
    """A run must not start against an image that cannot serve a completion check."""

    def test_the_shipped_image_passes(self, box: Sandbox) -> None:
        box.preflight()  # must not raise

    def test_the_shipped_image_passes_protocol_2_identity_policy(self, box: Sandbox) -> None:
        """The live daemon's manifest/config identity representation is explicitly approved."""
        box.preflight_benchmark(REPOSITORY)  # must not raise

    def test_an_image_without_pytest_is_refused_with_a_remedy(
        self,
        image_without_pytest: str,
    ) -> None:
        """THE bug this whole module exists for: it would have zeroed every score silently."""
        bare = Sandbox(isolation=Isolation.DOCKER, image=image_without_pytest)

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
        sandbox = Sandbox(isolation=Isolation.DOCKER)
        sandbox.preflight()
        validate_scenario(t02_dir, t02, sandbox=sandbox)
