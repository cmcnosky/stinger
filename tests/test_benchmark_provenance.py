"""Mechanical benchmark runtime-provenance preflight tests."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

import stinger.benchmark.provenance as provenance_module
from stinger import BENCHMARK_PROTOCOL_VERSION
from stinger.adapters.claude_code import ClaudeCodeAdapter
from stinger.adapters.cli_base import AdapterSettingsError
from stinger.adapters.codex import CodexAdapter
from stinger.benchmark.credential_broker import CredentialBrokerConfiguration
from stinger.benchmark.git_checkout import (
    DirtyGitCheckoutError,
    GitCheckoutError,
    VerifiedTrackedImplementation,
)
from stinger.benchmark.protocol import ProviderId, compiled_credential_isolation_policy
from stinger.benchmark.provenance import RuntimePreflightError, verify_runtime_provenance
from stinger.benchmark.verification_image import (
    APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID,
    VerifiedVerificationImage,
    canonical_verification_image_policy_sha256,
    compiled_verification_image_policy,
)
from stinger.config import AgentConfig, RunConfig
from stinger.docker_runtime import (
    DockerImageIdentity,
    DockerRuntimeIdentity,
    resolve_docker_client,
)

DIGEST_A = f"sha256:{'a' * 64}"
DIGEST_B = APPROVED_LINUX_ARM64_VERIFICATION_IMAGE_ID
COMMIT = "c" * 40


@pytest.fixture(autouse=True)
def _approved_verification_image_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep provenance-unit tests focused while returning a fully policy-bound verifier."""

    def approve(
        *,
        repository: Path,
        image: str,
        policy: object,
        docker_runtime: DockerRuntimeIdentity | None = None,
    ) -> VerifiedVerificationImage:
        del repository, image, policy
        assert docker_runtime is not None
        return VerifiedVerificationImage(
            policy_sha256=canonical_verification_image_policy_sha256(
                compiled_verification_image_policy()
            ),
            source_inventory_sha256=(compiled_verification_image_policy().source_inventory_sha256),
            image=DockerImageIdentity(
                image_id=DIGEST_B,
                repo_digests=(),
                operating_system="linux",
                architecture="arm64",
            ),
            docker_runtime=docker_runtime,
        )

    monkeypatch.setattr(provenance_module, "verify_approved_verification_image", approve)
    monkeypatch.setattr(
        provenance_module,
        "broker_source_inventory_sha256",
        lambda repository: compiled_credential_isolation_policy().broker_source_inventory_sha256,
    )


def _create_clean_unrelated_checkout(root: Path) -> str:
    """Create a real clean checkout that cannot contain the loaded Stinger modules."""
    source = root / "src" / "stinger"
    source.mkdir(parents=True)
    (source / "__init__.py").write_text('"""Unrelated fixture."""\n', encoding="utf-8")
    environment = {
        "GIT_AUTHOR_NAME": "fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.test",
        "GIT_COMMITTER_NAME": "fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.test",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    commands = (
        ("init", "--quiet", "--initial-branch", "main"),
        ("add", "--all"),
        ("commit", "--quiet", "--message", "fixture"),
    )
    for arguments in commands:
        completed = subprocess.run(
            ["/usr/bin/git", "-C", str(root), *arguments],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
    completed = subprocess.run(
        ["/usr/bin/git", "-C", str(root), "rev-parse", "HEAD"],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


def _fixture_docker_runtime() -> DockerRuntimeIdentity:
    """Return a deterministic runtime for provenance-boundary composition tests."""
    client = resolve_docker_client()
    return DockerRuntimeIdentity(
        client_path=str(client),
        client_sha256=hashlib.sha256(client.read_bytes()).hexdigest(),
        client_version="29.0.0",
        context_name="fixture-context",
        context_endpoint="unix:///tmp/fixture-docker.sock",
        context_endpoint_sha256="f" * 64,
        server_platform="fixture-engine",
        server_version="29.0.0",
        server_api_version="1.50",
        server_os="linux",
        server_arch="amd64",
    )


def benchmark_config(*, commit: str = COMMIT) -> RunConfig:
    """Return one fully declared contained benchmark configuration."""
    return RunConfig(
        agent=AgentConfig(
            adapter="codex",
            provider=ProviderId.OPENAI,
            model="gpt-test",
            cli_version="codex-cli 1.2.3",
            reasoning_effort="high",
            inference_settings={"model_verbosity": "low"},
            api_key_env="OPENAI_API_KEY",
            container_image="agent:1",
            container_image_digest=DIGEST_A,
            credential_broker=CredentialBrokerConfiguration(
                image="verification:1",
                image_digest=DIGEST_B,
            ),
        ),
        image="verification:1",
        verification_image_digest=DIGEST_B,
        stinger_commit=commit,
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
    )


def fake_runtime(
    *,
    calls: list[list[str]] | None = None,
) -> object:
    """Build a subprocess.run replacement with deterministic local observations."""

    def run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if calls is not None:
            calls.append(list(argv))
        if argv[0] == str(resolve_docker_client()):
            docker_args = argv[1:]
            if docker_args[:2] == ["context", "show"]:
                return subprocess.CompletedProcess(argv, 0, "test-context\n", "")
            if docker_args[:2] == ["context", "inspect"]:
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    json.dumps(
                        [{"Endpoints": {"docker": {"Host": "unix:///tmp/test-docker.sock"}}}]
                    ),
                    "",
                )
            if "version" in docker_args and "--format" in docker_args:
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    json.dumps(
                        {
                            "Client": {"Version": "29.0.0"},
                            "Server": {
                                "Platform": {"Name": "test-engine"},
                                "Version": "29.0.0",
                                "ApiVersion": "1.50",
                                "Os": "linux",
                                "Arch": "amd64",
                            },
                        }
                    ),
                    "",
                )
            if "image" in docker_args and "inspect" in docker_args:
                image = docker_args[-1]
                digest = DIGEST_A if image == "agent:1" else DIGEST_B
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    json.dumps(
                        [
                            {
                                "Id": digest,
                                "RepoDigests": [],
                                "Os": "linux",
                                "Architecture": "arm64",
                            }
                        ]
                    ),
                    "",
                )
            if "run" in docker_args:
                return subprocess.CompletedProcess(argv, 0, "codex-cli 1.2.3\n", "")
        if argv[:3] == ["docker", "image", "inspect"]:
            digest = DIGEST_A if argv[3] == "agent:1" else DIGEST_B
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    [
                        {
                            "Id": digest,
                            "RepoDigests": [],
                            "Os": "linux",
                            "Architecture": "arm64",
                        }
                    ]
                ),
                "",
            )
        raise AssertionError(f"unexpected probe: {argv}")

    return run


def test_preflight_records_observed_images_cli_commit_and_resolved_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = benchmark_config()
    adapter = CodexAdapter(config.agent)
    calls: list[list[str]] = []
    shim = tmp_path / "docker"
    shim.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("DOCKER_HOST", "tcp://attacker.invalid:2375")
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "redirected.git"))
    monkeypatch.setattr(
        provenance_module,
        "verify_loaded_stinger_implementation",
        lambda repository, *, expected_commit, timeout: VerifiedTrackedImplementation(
            commit=expected_commit,
            files=(),
            inventory_sha256="d" * 64,
        ),
    )
    monkeypatch.setattr(subprocess, "run", fake_runtime(calls=calls))

    observed = verify_runtime_provenance(
        config,
        adapter,
        workdir=tmp_path,
        repository=tmp_path,
    )

    assert observed.verified is True
    assert observed.stinger_commit == COMMIT
    assert observed.agent_container_image_id == DIGEST_A
    assert observed.verification_image_id == DIGEST_B
    assert observed.agent_cli_version == "codex-cli 1.2.3"
    assert observed.credential_isolation is not None
    assert observed.credential_isolation.verified is True
    assert observed.resolved_version_invocation == ("codex", "--version")
    assert str(tmp_path) not in observed.model_dump_json()
    assert "gpt-test" in observed.resolved_agent_invocation
    assert 'model_reasoning_effort="high"' in observed.resolved_agent_invocation
    assert 'model_verbosity="low"' in observed.resolved_agent_invocation
    assert adapter.config.container_image == DIGEST_A
    assert adapter.config.credential_broker is not None
    assert adapter.config.credential_broker.image == DIGEST_B
    fixed_docker = str(resolve_docker_client())
    docker_calls = [argv for argv in calls if argv and argv[0] == fixed_docker]
    assert docker_calls
    assert all(argv[0] != str(shim) for argv in docker_calls)
    assert not any(argv and argv[0] == "git" for argv in calls)


@pytest.mark.parametrize(
    ("mutation", "expected_issue"),
    [
        ("missing", "credential_broker_configuration_missing"),
        ("image", "credential_broker_image_identity_mismatch"),
        ("source", "credential_broker_source_not_protocol_approved"),
    ],
)
def test_preflight_fails_closed_on_missing_or_mismatched_broker_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected_issue: str,
) -> None:
    config = benchmark_config()
    if mutation == "missing":
        config = config.model_copy(
            update={
                "agent": config.agent.model_copy(update={"credential_broker": None}),
            }
        )
    elif mutation == "image":
        assert config.agent.credential_broker is not None
        config = config.model_copy(
            update={
                "agent": config.agent.model_copy(
                    update={
                        "credential_broker": config.agent.credential_broker.model_copy(
                            update={"image": "agent:1"}
                        )
                    }
                )
            }
        )
    else:
        monkeypatch.setattr(
            provenance_module,
            "broker_source_inventory_sha256",
            lambda repository: "9" * 64,
        )
    monkeypatch.setattr(
        provenance_module,
        "verify_loaded_stinger_implementation",
        lambda repository, *, expected_commit, timeout: VerifiedTrackedImplementation(
            commit=expected_commit,
            files=(),
            inventory_sha256="d" * 64,
        ),
    )
    monkeypatch.setattr(subprocess, "run", fake_runtime())

    with pytest.raises(RuntimePreflightError, match=expected_issue):
        verify_runtime_provenance(
            config,
            CodexAdapter(config.agent),
            workdir=tmp_path,
            repository=tmp_path,
        )


def test_containerized_version_probe_uses_only_an_empty_temporary_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = benchmark_config()
    observations: list[tuple[Path, tuple[Path, ...], list[str]]] = []
    base_run = fake_runtime()
    monkeypatch.setattr(
        provenance_module,
        "verify_loaded_stinger_implementation",
        lambda repository, *, expected_commit, timeout: VerifiedTrackedImplementation(
            commit=expected_commit,
            files=(),
            inventory_sha256="d" * 64,
        ),
    )

    def observe_run(
        argv: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        if "run" in argv and DIGEST_A in argv:
            cwd = kwargs["cwd"]
            assert isinstance(cwd, Path)
            observations.append((cwd, tuple(cwd.iterdir()), list(argv)))
        return base_run(argv, **kwargs)  # type: ignore[operator]

    monkeypatch.setattr(subprocess, "run", observe_run)

    verify_runtime_provenance(
        config,
        CodexAdapter(config.agent),
        workdir=tmp_path,
        repository=tmp_path,
    )

    [(probe_workspace, contents, argv)] = observations
    assert probe_workspace != tmp_path
    assert contents == ()
    assert str(tmp_path.resolve()) not in argv
    assert argv[argv.index("--name") + 1].startswith("stinger-version-")
    assert f"{probe_workspace.resolve()}:/work" in argv


def test_containerized_version_probe_timeout_stops_the_named_container(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = benchmark_config()
    terminated: list[tuple[str, DockerRuntimeIdentity, int]] = []
    base_run = fake_runtime()
    monkeypatch.setattr(
        provenance_module,
        "verify_loaded_stinger_implementation",
        lambda repository, *, expected_commit, timeout: VerifiedTrackedImplementation(
            commit=expected_commit,
            files=(),
            inventory_sha256="d" * 64,
        ),
    )

    def time_out_version(
        argv: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        if "run" in argv and DIGEST_A in argv:
            raise subprocess.TimeoutExpired(argv, 30, output="partial")
        return base_run(argv, **kwargs)  # type: ignore[operator]

    def terminate(
        name: str,
        *,
        runtime: DockerRuntimeIdentity,
        timeout: int,
    ) -> None:
        terminated.append((name, runtime, timeout))

    monkeypatch.setattr(subprocess, "run", time_out_version)
    monkeypatch.setattr(provenance_module, "terminate_docker_container", terminate)

    with pytest.raises(RuntimePreflightError, match="agent_cli_version_unobservable"):
        verify_runtime_provenance(
            config,
            CodexAdapter(config.agent),
            workdir=tmp_path,
            repository=tmp_path,
        )

    [(container_name, _runtime, cleanup_timeout)] = terminated
    assert container_name.startswith("stinger-version-")
    assert cleanup_timeout == 30


def test_containerized_version_probe_timeout_fails_when_cleanup_is_unverified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = benchmark_config()
    base_run = fake_runtime()
    monkeypatch.setattr(
        provenance_module,
        "verify_loaded_stinger_implementation",
        lambda repository, *, expected_commit, timeout: VerifiedTrackedImplementation(
            commit=expected_commit,
            files=(),
            inventory_sha256="d" * 64,
        ),
    )

    def time_out_version(
        argv: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        if "run" in argv and DIGEST_A in argv:
            raise subprocess.TimeoutExpired(argv, 30)
        return base_run(argv, **kwargs)  # type: ignore[operator]

    monkeypatch.setattr(subprocess, "run", time_out_version)
    monkeypatch.setattr(
        provenance_module,
        "terminate_docker_container",
        lambda name, *, runtime, timeout: (_ for _ in ()).throw(
            provenance_module.DockerRuntimeError("still running")
        ),
    )

    with pytest.raises(
        RuntimePreflightError,
        match="agent_cli_version_container_termination_unverified",
    ):
        verify_runtime_provenance(
            config,
            CodexAdapter(config.agent),
            workdir=tmp_path,
            repository=tmp_path,
        )


def test_containerized_version_probe_nonzero_cleans_before_rejecting_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = benchmark_config()
    base_run = fake_runtime()
    terminated: list[tuple[str, DockerRuntimeIdentity, int]] = []
    monkeypatch.setattr(
        provenance_module,
        "verify_loaded_stinger_implementation",
        lambda repository, *, expected_commit, timeout: VerifiedTrackedImplementation(
            commit=expected_commit,
            files=(),
            inventory_sha256="d" * 64,
        ),
    )

    def fail_version(
        argv: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        if "run" in argv and DIGEST_A in argv:
            return subprocess.CompletedProcess(argv, -9, "untrusted output", "")
        return base_run(argv, **kwargs)  # type: ignore[operator]

    monkeypatch.setattr(subprocess, "run", fail_version)
    monkeypatch.setattr(
        provenance_module,
        "terminate_docker_container",
        lambda name, *, runtime, timeout: terminated.append((name, runtime, timeout)),
    )

    with pytest.raises(RuntimePreflightError, match="agent_cli_version_unobservable"):
        verify_runtime_provenance(
            config,
            CodexAdapter(config.agent),
            workdir=tmp_path,
            repository=tmp_path,
        )

    [(name, runtime, timeout)] = terminated
    assert name.startswith("stinger-version-")
    assert runtime.context_endpoint == "unix:///tmp/test-docker.sock"
    assert timeout == 30


def test_containerized_version_probe_oserror_cleans_before_failing_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = benchmark_config()
    base_run = fake_runtime()
    terminated: list[str] = []
    monkeypatch.setattr(
        provenance_module,
        "verify_loaded_stinger_implementation",
        lambda repository, *, expected_commit, timeout: VerifiedTrackedImplementation(
            commit=expected_commit,
            files=(),
            inventory_sha256="d" * 64,
        ),
    )

    def fail_version(
        argv: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        if "run" in argv and DIGEST_A in argv:
            raise OSError("client failed after launch")
        return base_run(argv, **kwargs)  # type: ignore[operator]

    monkeypatch.setattr(subprocess, "run", fail_version)
    monkeypatch.setattr(
        provenance_module,
        "terminate_docker_container",
        lambda name, *, runtime, timeout: terminated.append(name),
    )

    with pytest.raises(RuntimePreflightError, match="agent_cli_version_unobservable"):
        verify_runtime_provenance(
            config,
            CodexAdapter(config.agent),
            workdir=tmp_path,
            repository=tmp_path,
        )

    assert len(terminated) == 1
    assert terminated[0].startswith("stinger-version-")


@pytest.mark.parametrize(
    "interruption",
    [KeyboardInterrupt(), SystemExit(29), BaseException("synthetic stop")],
    ids=["keyboard-interrupt", "system-exit", "base-exception"],
)
def test_containerized_version_probe_interrupt_cleans_then_reraises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interruption: BaseException,
) -> None:
    config = benchmark_config()
    base_run = fake_runtime()
    terminated: list[str] = []
    monkeypatch.setattr(
        provenance_module,
        "verify_loaded_stinger_implementation",
        lambda repository, *, expected_commit, timeout: VerifiedTrackedImplementation(
            commit=expected_commit,
            files=(),
            inventory_sha256="d" * 64,
        ),
    )

    def interrupt_version(
        argv: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        if "run" in argv and DIGEST_A in argv:
            raise interruption
        return base_run(argv, **kwargs)  # type: ignore[operator]

    monkeypatch.setattr(subprocess, "run", interrupt_version)
    monkeypatch.setattr(
        provenance_module,
        "terminate_docker_container",
        lambda name, *, runtime, timeout: terminated.append(name),
    )

    with pytest.raises(type(interruption)):
        verify_runtime_provenance(
            config,
            CodexAdapter(config.agent),
            workdir=tmp_path,
            repository=tmp_path,
        )

    assert len(terminated) == 1
    assert terminated[0].startswith("stinger-version-")


def test_containerized_version_probe_nonzero_aborts_when_cleanup_is_unverified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = benchmark_config()
    base_run = fake_runtime()
    monkeypatch.setattr(
        provenance_module,
        "verify_loaded_stinger_implementation",
        lambda repository, *, expected_commit, timeout: VerifiedTrackedImplementation(
            commit=expected_commit,
            files=(),
            inventory_sha256="d" * 64,
        ),
    )

    def fail_version(
        argv: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        if "run" in argv and DIGEST_A in argv:
            return subprocess.CompletedProcess(argv, 19, "must not escape", "")
        return base_run(argv, **kwargs)  # type: ignore[operator]

    monkeypatch.setattr(subprocess, "run", fail_version)
    monkeypatch.setattr(
        provenance_module,
        "terminate_docker_container",
        lambda name, *, runtime, timeout: (_ for _ in ()).throw(
            provenance_module.DockerRuntimeError("still running")
        ),
    )

    with pytest.raises(
        RuntimePreflightError,
        match="agent_cli_version_container_termination_unverified",
    ):
        verify_runtime_provenance(
            config,
            CodexAdapter(config.agent),
            workdir=tmp_path,
            repository=tmp_path,
        )


def test_preflight_refuses_a_dirty_stinger_worktree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = benchmark_config()
    monkeypatch.setattr(subprocess, "run", fake_runtime())

    def dirty_checkout(
        repository: Path,
        *,
        expected_commit: str,
        timeout: int,
    ) -> VerifiedTrackedImplementation:
        del repository, expected_commit, timeout
        raise DirtyGitCheckoutError("dirty")

    monkeypatch.setattr(
        provenance_module,
        "verify_loaded_stinger_implementation",
        dirty_checkout,
    )

    with pytest.raises(RuntimePreflightError, match="stinger_worktree_dirty"):
        verify_runtime_provenance(
            config,
            CodexAdapter(config.agent),
            workdir=tmp_path,
            repository=tmp_path,
        )


def test_preflight_refuses_an_unrelated_clean_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = tmp_path / "unrelated"
    checkout.mkdir()
    commit = _create_clean_unrelated_checkout(checkout)
    config = benchmark_config(commit=commit)
    runtime = _fixture_docker_runtime()
    monkeypatch.setattr(provenance_module, "observe_docker_runtime", lambda: runtime)
    monkeypatch.setattr(
        provenance_module,
        "verify_docker_runtime",
        lambda expected: expected,
    )
    monkeypatch.setattr(
        provenance_module,
        "inspect_docker_image",
        lambda image, *, runtime: (
            DIGEST_A if image == "agent:1" else DIGEST_B,
            (),
        ),
    )
    monkeypatch.setattr(
        provenance_module,
        "_command_output",
        lambda *args, **kwargs: "codex-cli 1.2.3",
    )

    with pytest.raises(
        RuntimePreflightError,
        match="stinger_loaded_implementation_unverified",
    ):
        verify_runtime_provenance(
            config,
            CodexAdapter(config.agent),
            workdir=tmp_path,
            repository=checkout,
        )


def test_preflight_refuses_a_mixed_loaded_module_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = benchmark_config()
    monkeypatch.setattr(subprocess, "run", fake_runtime())

    def mixed_modules(
        repository: Path,
        *,
        expected_commit: str,
        timeout: int,
    ) -> VerifiedTrackedImplementation:
        del repository, expected_commit, timeout
        raise GitCheckoutError("loaded module is outside the supplied checkout")

    monkeypatch.setattr(
        provenance_module,
        "verify_loaded_stinger_implementation",
        mixed_modules,
    )

    with pytest.raises(
        RuntimePreflightError,
        match="stinger_loaded_implementation_unverified",
    ):
        verify_runtime_provenance(
            config,
            CodexAdapter(config.agent),
            workdir=tmp_path,
            repository=tmp_path,
        )


def test_preflight_refuses_implementation_mutation_between_probes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = benchmark_config()
    monkeypatch.setattr(subprocess, "run", fake_runtime())
    calls = 0

    def changing_implementation(
        repository: Path,
        *,
        expected_commit: str,
        timeout: int,
    ) -> VerifiedTrackedImplementation:
        nonlocal calls
        del repository, timeout
        calls += 1
        return VerifiedTrackedImplementation(
            commit=expected_commit,
            files=(),
            inventory_sha256=("d" if calls == 1 else "e") * 64,
        )

    monkeypatch.setattr(
        provenance_module,
        "verify_loaded_stinger_implementation",
        changing_implementation,
    )

    with pytest.raises(
        RuntimePreflightError,
        match="stinger_loaded_implementation_changed",
    ):
        verify_runtime_provenance(
            config,
            CodexAdapter(config.agent),
            workdir=tmp_path,
            repository=tmp_path,
        )
    assert calls == 2


def test_adapter_fails_closed_when_it_cannot_apply_declared_inference_settings() -> None:
    adapter = ClaudeCodeAdapter(
        AgentConfig(
            adapter="claude-code",
            reasoning_effort="high",
            inference_settings={"temperature": 0.0},
        )
    )

    with pytest.raises(AdapterSettingsError, match="cannot apply"):
        adapter.argv("{prompt}")
