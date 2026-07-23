"""Mechanical benchmark runtime-provenance preflight tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from stinger import BENCHMARK_PROTOCOL_VERSION
from stinger.adapters.claude_code import ClaudeCodeAdapter
from stinger.adapters.cli_base import AdapterSettingsError
from stinger.adapters.codex import CodexAdapter
from stinger.benchmark.protocol import ProviderId
from stinger.benchmark.provenance import RuntimePreflightError, verify_runtime_provenance
from stinger.config import AgentConfig, RunConfig

DIGEST_A = f"sha256:{'a' * 64}"
DIGEST_B = f"sha256:{'b' * 64}"
COMMIT = "c" * 40


def benchmark_config() -> RunConfig:
    """Return one fully declared contained benchmark configuration."""
    return RunConfig(
        agent=AgentConfig(
            adapter="codex",
            provider=ProviderId.OPENAI,
            model="gpt-test",
            cli_version="codex-cli 1.2.3",
            reasoning_effort="high",
            inference_settings={"model_verbosity": "low"},
            container_image="agent:1",
            container_image_digest=DIGEST_A,
        ),
        image="verification:1",
        verification_image_digest=DIGEST_B,
        stinger_commit=COMMIT,
        benchmark_protocol_version=BENCHMARK_PROTOCOL_VERSION,
    )


def fake_runtime(
    *,
    dirty: bool = False,
) -> object:
    """Build a subprocess.run replacement with deterministic local observations."""

    def run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[:4] == ["git", "-C", argv[2], "rev-parse"]:
            return subprocess.CompletedProcess(argv, 0, f"{COMMIT}\n", "")
        if argv[:4] == ["git", "-C", argv[2], "status"]:
            status = " M src/stinger/config.py\n" if dirty else ""
            return subprocess.CompletedProcess(argv, 0, status, "")
        if argv[:3] == ["docker", "image", "inspect"]:
            digest = DIGEST_A if argv[3] == "agent:1" else DIGEST_B
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps([{"Id": digest, "RepoDigests": []}]),
                "",
            )
        if argv[:2] == ["docker", "run"]:
            return subprocess.CompletedProcess(argv, 0, "codex-cli 1.2.3\n", "")
        raise AssertionError(f"unexpected probe: {argv}")

    return run


def test_preflight_records_observed_images_cli_commit_and_resolved_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = benchmark_config()
    monkeypatch.setattr(subprocess, "run", fake_runtime())

    observed = verify_runtime_provenance(
        config,
        CodexAdapter(config.agent),
        workdir=tmp_path,
        repository=tmp_path,
    )

    assert observed.verified is True
    assert observed.stinger_commit == COMMIT
    assert observed.agent_container_image_id == DIGEST_A
    assert observed.verification_image_id == DIGEST_B
    assert observed.agent_cli_version == "codex-cli 1.2.3"
    assert observed.resolved_version_invocation == ("codex", "--version")
    assert str(tmp_path) not in observed.model_dump_json()
    assert "gpt-test" in observed.resolved_agent_invocation
    assert 'model_reasoning_effort="high"' in observed.resolved_agent_invocation
    assert 'model_verbosity="low"' in observed.resolved_agent_invocation


def test_preflight_refuses_a_dirty_stinger_worktree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = benchmark_config()
    monkeypatch.setattr(subprocess, "run", fake_runtime(dirty=True))

    with pytest.raises(RuntimePreflightError, match="stinger_worktree_dirty"):
        verify_runtime_provenance(
            config,
            CodexAdapter(config.agent),
            workdir=tmp_path,
            repository=tmp_path,
        )


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
