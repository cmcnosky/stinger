"""Fixed Docker client, environment, and runtime-identity boundary tests."""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

import stinger.docker_runtime as docker_runtime
from stinger.docker_runtime import (
    DockerRuntimeError,
    DockerRuntimeIdentity,
    docker_command_argv,
    docker_environment,
    inspect_docker_image_identity,
    observe_docker_runtime,
    resolve_docker_client,
    terminate_docker_container,
)


def _fixture_runtime() -> DockerRuntimeIdentity:
    """Return a bounded runtime identity for cleanup-composition tests."""
    return DockerRuntimeIdentity(
        client_path="/usr/bin/docker",
        client_sha256="a" * 64,
        client_version="29.0.0",
        context_name="fixture",
        context_endpoint="unix:///tmp/fixture.sock",
        context_endpoint_sha256="b" * 64,
        server_platform="fixture-engine",
        server_version="29.0.0",
        server_api_version="1.50",
        server_os="linux",
        server_arch="amd64",
    )


def _fake_observation(
    calls: list[tuple[list[str], dict[str, str]]],
) -> object:
    """Return deterministic Docker observations while retaining exact argv/env."""

    def run(
        argv: list[str],
        *,
        env: dict[str, str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        calls.append((list(argv), dict(env)))
        if argv[1:] == ["context", "show"]:
            return subprocess.CompletedProcess(argv, 0, "fixture-context\n", "")
        if argv[1:3] == ["context", "inspect"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    [
                        {
                            "Endpoints": {
                                "docker": {
                                    "Host": "unix:///tmp/fixture-docker.sock",
                                    "SkipTLSVerify": False,
                                }
                            },
                            "TLSMaterial": {},
                        }
                    ]
                ),
                "",
            )
        if "version" in argv:
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    {
                        "Client": {"Version": "29.0.0"},
                        "Server": {
                            "Platform": {"Name": "fixture-engine"},
                            "Version": "29.0.0",
                            "ApiVersion": "1.50",
                            "Os": "linux",
                            "Arch": "amd64",
                        },
                    }
                ),
                "",
            )
        raise AssertionError(argv)

    return run


def test_path_shim_cannot_supply_the_docker_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An executable named docker in caller PATH is never inspected or launched."""
    shim = tmp_path / "docker"
    shim.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("DOCKER_HOST", "tcp://attacker.invalid:2375")
    calls: list[tuple[list[str], dict[str, str]]] = []
    monkeypatch.setattr(subprocess, "run", _fake_observation(calls))
    monkeypatch.setattr(docker_runtime, "_active_runtime", None)

    observed = observe_docker_runtime()

    fixed = str(resolve_docker_client())
    assert calls
    assert all(argv[0] == fixed for argv, _ in calls)
    assert all(argv[0] != str(shim) for argv, _ in calls)
    assert all("DOCKER_HOST" not in environment for _, environment in calls)
    assert observed.client_path == fixed
    assert docker_command_argv(["run", "--rm", "image"], runtime=observed)[:3] == [
        fixed,
        "--host",
        "unix:///tmp/fixture-docker.sock",
    ]


def test_image_identity_includes_the_daemon_reported_target_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _fixture_runtime()
    monkeypatch.setattr(
        docker_runtime,
        "run_docker",
        lambda arguments, **kwargs: subprocess.CompletedProcess(
            list(arguments),
            0,
            json.dumps(
                [
                    {
                        "Id": "sha256:" + "c" * 64,
                        "RepoDigests": ["example.invalid/runner@sha256:" + "d" * 64],
                        "Os": "linux",
                        "Architecture": "arm64",
                    }
                ]
            ),
            "",
        ),
    )

    identity = inspect_docker_image_identity("runner:tag", runtime=runtime)

    assert identity.image_id == "sha256:" + "c" * 64
    assert identity.platform == "linux/arm64"
    assert identity.repo_digests == ("example.invalid/runner@sha256:" + "d" * 64,)


def test_runtime_calls_ignore_later_home_docker_config_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After discovery, execution pins the endpoint and uses an empty Docker config."""
    calls: list[tuple[list[str], dict[str, str]]] = []
    monkeypatch.setattr(subprocess, "run", _fake_observation(calls))
    monkeypatch.setattr(docker_runtime, "_active_runtime", None)
    home = tmp_path / "home"
    config = home / ".docker" / "config.json"
    config.parent.mkdir(parents=True)
    config.write_text('{"proxies":{"default":{"httpProxy":"http://one.invalid"}}}\n')
    monkeypatch.setenv("HOME", str(home))
    observed = observe_docker_runtime()

    config.write_text('{"proxies":{"default":{"httpProxy":"http://two.invalid"}}}\n')
    environment = docker_environment(os.environ)
    argv = docker_command_argv(["run", "--rm", "image"], runtime=observed)

    assert environment["HOME"] == "/var/empty"
    assert environment["DOCKER_CONFIG"] == "/var/empty"
    assert argv[1:3] == ["--host", "unix:///tmp/fixture-docker.sock"]


def test_forwarded_docker_or_loader_overrides_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DOCKER_CONTEXT", "attacker")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/attacker.so")
    with pytest.raises(DockerRuntimeError, match="overrides are prohibited"):
        docker_environment(os.environ, forwarded_names=("DOCKER_CONTEXT",))
    with pytest.raises(DockerRuntimeError, match="overrides are prohibited"):
        docker_environment(os.environ, forwarded_names=("LD_PRELOAD",))


def test_timeout_cleanup_force_removes_a_running_container_and_proves_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _fixture_runtime()
    calls: list[tuple[str, ...]] = []
    verified: list[DockerRuntimeIdentity] = []
    sleeps: list[float] = []

    def run(
        arguments: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(arguments)
        return subprocess.CompletedProcess(
            list(arguments),
            0,
            "stinger-verifier-abc123\n" if arguments[0] == "rm" else "",
            "",
        )

    monkeypatch.setattr(docker_runtime, "run_docker", run)
    monkeypatch.setattr(
        docker_runtime,
        "verify_docker_runtime",
        lambda expected: verified.append(expected) or expected,
    )
    monkeypatch.setattr(docker_runtime.time, "sleep", sleeps.append)

    terminate_docker_container(
        "stinger-verifier-abc123",
        runtime=runtime,
        timeout=17,
    )

    assert calls == [
        ("rm", "--force", "stinger-verifier-abc123"),
        (
            "ps",
            "--all",
            "--quiet",
            "--filter",
            "name=^/stinger-verifier-abc123$",
        ),
        ("rm", "--force", "stinger-verifier-abc123"),
        (
            "ps",
            "--all",
            "--quiet",
            "--filter",
            "name=^/stinger-verifier-abc123$",
        ),
    ]
    assert verified == [runtime]
    assert sleeps == [docker_runtime._CLEANUP_SETTLE_SECONDS]


def test_timeout_cleanup_removes_a_stopped_create_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _fixture_runtime()
    calls: list[tuple[str, ...]] = []

    def run(
        arguments: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(arguments)
        return subprocess.CompletedProcess(list(arguments), 0, "", "")

    monkeypatch.setattr(docker_runtime, "run_docker", run)
    monkeypatch.setattr(
        docker_runtime,
        "verify_docker_runtime",
        lambda expected: expected,
    )
    monkeypatch.setattr(docker_runtime.time, "sleep", lambda _seconds: None)

    terminate_docker_container("stinger-create-abc123", runtime=runtime)

    assert calls[0] == ("rm", "--force", "stinger-create-abc123")
    assert all("--all" in arguments for arguments in calls if arguments[0] == "ps")


@pytest.mark.parametrize(
    "interruption",
    [KeyboardInterrupt(), SystemExit(31)],
    ids=["keyboard-interrupt", "system-exit"],
)
def test_timeout_cleanup_finishes_proof_before_reraising_interrupt(
    monkeypatch: pytest.MonkeyPatch,
    interruption: BaseException,
) -> None:
    """One ordinary interrupt cannot abandon exact-name cleanup mid-proof."""
    runtime = _fixture_runtime()
    calls: list[tuple[str, ...]] = []
    verified: list[DockerRuntimeIdentity] = []
    interrupted = False

    def run(
        arguments: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal interrupted
        del kwargs
        calls.append(arguments)
        if not interrupted and arguments[0] == "ps":
            interrupted = True
            raise interruption
        return subprocess.CompletedProcess(list(arguments), 0, "", "")

    monkeypatch.setattr(docker_runtime, "run_docker", run)

    def verify(expected: DockerRuntimeIdentity) -> DockerRuntimeIdentity:
        verified.append(expected)
        return expected

    monkeypatch.setattr(docker_runtime, "verify_docker_runtime", verify)
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)

    with pytest.raises(type(interruption)) as raised:
        terminate_docker_container("stinger-verifier-interrupted", runtime=runtime)

    assert raised.value is interruption
    assert verified == [runtime]
    assert [arguments[0] for arguments in calls] == ["rm", "ps", "rm", "ps", "rm", "ps"]


def test_timeout_cleanup_retains_enough_attempts_after_a_late_sleep_interrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A late first interrupt does not consume the observations needed for proof."""
    runtime = _fixture_runtime()
    observed_states = iter(("present\n", "present\n", "", "", ""))
    sleep_calls = 0
    interruption = SystemExit(31)

    def run(
        arguments: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        return subprocess.CompletedProcess(
            list(arguments),
            0,
            next(observed_states) if arguments[0] == "ps" else "",
            "",
        )

    def settle(_seconds: float) -> None:
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls == 3:
            raise interruption

    monkeypatch.setattr(docker_runtime, "run_docker", run)
    monkeypatch.setattr(
        docker_runtime,
        "verify_docker_runtime",
        lambda expected: expected,
    )
    monkeypatch.setattr(time, "sleep", settle)

    with pytest.raises(SystemExit) as raised:
        terminate_docker_container("stinger-verifier-late-interrupt", runtime=runtime)

    assert raised.value is interruption
    assert sleep_calls == 4


def test_timeout_cleanup_retries_runtime_proof_before_reraising_interrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An interrupt in final runtime re-verification is shielded exactly once."""
    runtime = _fixture_runtime()
    interruption = KeyboardInterrupt()
    verification_calls = 0

    monkeypatch.setattr(
        docker_runtime,
        "run_docker",
        lambda arguments, **kwargs: subprocess.CompletedProcess(
            list(arguments),
            0,
            "",
            "",
        ),
    )

    def verify(expected: DockerRuntimeIdentity) -> DockerRuntimeIdentity:
        nonlocal verification_calls
        verification_calls += 1
        if verification_calls == 1:
            raise interruption
        return expected

    monkeypatch.setattr(docker_runtime, "verify_docker_runtime", verify)
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)

    with pytest.raises(KeyboardInterrupt) as raised:
        terminate_docker_container("stinger-verifier-runtime-interrupt", runtime=runtime)

    assert raised.value is interruption
    assert verification_calls == 2


def test_timeout_cleanup_uncertainty_overrides_a_retained_interrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An interrupt is not re-raised as though cleanup succeeded when the name remains."""
    runtime = _fixture_runtime()
    interrupted = False

    def run(
        arguments: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal interrupted
        del kwargs
        if not interrupted and arguments[0] == "rm":
            interrupted = True
            raise KeyboardInterrupt
        return subprocess.CompletedProcess(
            list(arguments),
            0,
            "still-present\n" if arguments[0] == "ps" else "",
            "",
        )

    monkeypatch.setattr(docker_runtime, "run_docker", run)
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)

    with pytest.raises(DockerRuntimeError, match="absence was not verified"):
        terminate_docker_container("stinger-verifier-interrupted", runtime=runtime)


def test_timeout_cleanup_accepts_nonzero_remove_only_when_name_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _fixture_runtime()
    calls: list[tuple[str, ...]] = []

    def run(
        arguments: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(arguments)
        return subprocess.CompletedProcess(
            list(arguments),
            1 if arguments[0] == "rm" else 0,
            "",
            "No such container" if arguments[0] == "rm" else "",
        )

    monkeypatch.setattr(docker_runtime, "run_docker", run)
    monkeypatch.setattr(
        docker_runtime,
        "verify_docker_runtime",
        lambda expected: expected,
    )
    monkeypatch.setattr(docker_runtime.time, "sleep", lambda _seconds: None)

    terminate_docker_container("stinger-verifier-absent", runtime=runtime)

    assert [arguments[0] for arguments in calls] == ["rm", "ps", "rm", "ps"]


@pytest.mark.parametrize("failed_command", ["rm", "ps"])
def test_timeout_cleanup_retries_a_transient_docker_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
    failed_command: str,
) -> None:
    """One client failure cannot abandon a possibly live exact-name container."""
    runtime = _fixture_runtime()
    calls: list[tuple[str, ...]] = []
    failed = False

    def run(
        arguments: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal failed
        del kwargs
        calls.append(arguments)
        if not failed and arguments[0] == failed_command:
            failed = True
            raise DockerRuntimeError("transient Docker client failure")
        return subprocess.CompletedProcess(
            list(arguments),
            0,
            (
                "still-present\n"
                if failed_command == "rm"
                and arguments[0] == "ps"
                and len([call for call in calls if call[0] == "ps"]) == 1
                else ""
            ),
            "",
        )

    monkeypatch.setattr(docker_runtime, "run_docker", run)
    monkeypatch.setattr(
        docker_runtime,
        "verify_docker_runtime",
        lambda expected: expected,
    )
    monkeypatch.setattr(docker_runtime.time, "sleep", lambda _seconds: None)

    terminate_docker_container("stinger-verifier-transient", runtime=runtime)

    assert [arguments[0] for arguments in calls] == ["rm", "ps", "rm", "ps", "rm", "ps"]


def test_timeout_cleanup_exhausts_transient_errors_before_failing_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unprovable absence still fails after every bounded removal opportunity."""
    runtime = _fixture_runtime()
    calls: list[tuple[str, ...]] = []

    def run(
        arguments: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(arguments)
        if arguments[0] == "ps":
            raise DockerRuntimeError("persistent Docker client failure")
        return subprocess.CompletedProcess(list(arguments), 0, "", "")

    monkeypatch.setattr(docker_runtime, "run_docker", run)
    monkeypatch.setattr(docker_runtime.time, "sleep", lambda _seconds: None)

    with pytest.raises(DockerRuntimeError, match="absence was not verified"):
        terminate_docker_container("stinger-verifier-unprovable", runtime=runtime)

    assert [arguments[0] for arguments in calls] == ["rm", "ps"] * 4


def test_timeout_cleanup_catches_a_container_that_appears_after_first_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _fixture_runtime()
    observed_states = iter(("", "late-container\n", "", ""))
    calls: list[tuple[str, ...]] = []

    def run(
        arguments: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(arguments)
        if arguments[0] == "rm":
            return subprocess.CompletedProcess(list(arguments), 1, "", "")
        return subprocess.CompletedProcess(list(arguments), 0, next(observed_states), "")

    monkeypatch.setattr(docker_runtime, "run_docker", run)
    monkeypatch.setattr(
        docker_runtime,
        "verify_docker_runtime",
        lambda expected: expected,
    )
    monkeypatch.setattr(docker_runtime.time, "sleep", lambda _seconds: None)

    terminate_docker_container("stinger-create-late", runtime=runtime)

    assert len([arguments for arguments in calls if arguments[0] == "ps"]) == 4


def test_timeout_cleanup_fails_when_remove_fails_and_name_remains_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _fixture_runtime()

    def run(
        arguments: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        return subprocess.CompletedProcess(
            list(arguments),
            1 if arguments[0] == "rm" else 0,
            "still-present\n" if arguments[0] == "ps" else "",
            "",
        )

    monkeypatch.setattr(docker_runtime, "run_docker", run)
    monkeypatch.setattr(
        docker_runtime,
        "verify_docker_runtime",
        lambda expected: expected,
    )
    monkeypatch.setattr(docker_runtime.time, "sleep", lambda _seconds: None)

    with pytest.raises(DockerRuntimeError, match="absence was not verified"):
        terminate_docker_container("stinger-verifier-abc123", runtime=runtime)


def test_timeout_cleanup_fails_when_all_state_inventory_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _fixture_runtime()
    monkeypatch.setattr(
        docker_runtime,
        "run_docker",
        lambda arguments, **kwargs: subprocess.CompletedProcess(
            list(arguments),
            1 if arguments[0] == "ps" else 0,
            "",
            "",
        ),
    )

    with pytest.raises(DockerRuntimeError, match="inventory failed"):
        terminate_docker_container("stinger-verifier-abc123", runtime=runtime)


def test_timeout_cleanup_fails_when_runtime_reverification_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _fixture_runtime()
    monkeypatch.setattr(
        docker_runtime,
        "run_docker",
        lambda arguments, **kwargs: subprocess.CompletedProcess(
            list(arguments),
            0,
            "",
            "",
        ),
    )

    def verify(expected: DockerRuntimeIdentity) -> DockerRuntimeIdentity:
        del expected
        raise DockerRuntimeError("runtime changed")

    monkeypatch.setattr(docker_runtime, "verify_docker_runtime", verify)
    monkeypatch.setattr(docker_runtime.time, "sleep", lambda _seconds: None)

    with pytest.raises(DockerRuntimeError, match="runtime changed"):
        terminate_docker_container("stinger-verifier-abc123", runtime=runtime)


def test_timeout_cleanup_rejects_an_untrusted_container_name() -> None:
    with pytest.raises(DockerRuntimeError, match="name is invalid"):
        terminate_docker_container(
            "stinger-verifier-a\n--filter=anything",
            runtime=_fixture_runtime(),
        )
