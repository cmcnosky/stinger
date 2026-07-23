"""Run configuration (SPEC.md §13) — what `stinger.yaml` declares.

The config fingerprint published in every Report is a sha256 over the *behavioural*
configuration: the adapter and its settings, the isolation mode and image, the repetition
count, the family filter, and the judge settings. It deliberately excludes filesystem
locations, because two machines running the same configuration from different directories
must produce the same fingerprint — otherwise `rerun.sh` could never demonstrate that a run
reproduced. Which corpus was used is pinned separately and more precisely by `corpus_hash`,
which covers content rather than a path (SPEC.md §10).

No secret ever enters this file or the fingerprint. An adapter names the *environment
variable* holding its API key (`api_key_env`), never the key itself, so a resolved config is
safe to commit next to the report it produced.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError, field_validator

from stinger.benchmark.protocol import (
    BenchmarkRunMetadata,
    ProviderId,
    canonical_agent_configuration_fingerprint,
)
from stinger.harness.sandbox import DEFAULT_IMAGE, Isolation
from stinger.models import Family

__all__ = ["DEFAULT_IMAGE", "AgentConfig", "ConfigError", "JudgeConfig", "RunConfig"]


class ConfigError(Exception):
    """Raised when a `stinger.yaml` cannot be read as a RunConfig."""


class AgentConfig(BaseModel):
    """Which agent is under test, and how to drive it (SPEC.md §5)."""

    # extra="forbid": an unknown key is a loud error, not a silent no-op. The stakes are not
    # cosmetic — a typo'd `regression_threshold` would gate nothing (CI green forever), and a
    # typo'd `container_image` would silently run the agent uncontained.
    model_config = ConfigDict(frozen=True, extra="forbid")

    adapter: str  # "claude-code" | "codex" | "aider" | "shell" | "recorded"
    model: str | None = None  # the agent's model id, when it has one; part of the fingerprint
    provider: ProviderId | None = None  # canonical provider; required for benchmark publication
    cli_version: str | None = None  # exact agent CLI/build version, not a floating channel
    reasoning_effort: str | None = None  # named reasoning mode, when the model exposes one
    inference_settings: dict[str, JsonValue] = Field(default_factory=dict)
    """Resolved inference parameters such as temperature, top-p, and max output tokens."""

    command: list[str] = []  # argv template for the generic `shell` adapter; needs "{prompt}"
    version_command: list[str] = []  # shell adapter CLI-version probe; no prompt or network
    api_key_env: str | None = None  # NAME of the env var holding the key — never the key
    fixture: Path | None = None  # recorded-run fixture directory, for the `recorded` adapter
    options: dict[str, str] = {}  # extra environment for the agent process; in the fingerprint

    # Image to run the agent inside. SPEC.md §5 requires the agent have no access outside its
    # workdir, and only a container delivers that; without one the agent is a host subprocess
    # with its cwd set, which is weaker and is documented as such in adapters/cli_base.py. The
    # image must already contain the agent CLI, which is why Stinger cannot supply a default.
    container_image: str | None = None
    container_image_digest: str | None = None
    """Resolved immutable digest of ``container_image``; required for benchmark publication."""

    # A host directory holding the agent's credentials, mounted READ-ONLY at /credentials in
    # the container. For CLIs that authenticate from a credential file rather than from an
    # environment variable — Codex under a ChatGPT subscription keeps OAuth tokens in
    # `auth.json`, and `api_key_env` cannot express that. Do NOT set CODEX_HOME to
    # /credentials: a read-only mount cannot be a CLI's live home, so the codex-agent image's
    # entrypoint copies /credentials into its own writable CODEX_HOME and rejects that value
    # outright. Leaving CODEX_HOME at the image default is all that is required.
    #
    # This is the one hole in "nothing but the workdir is mounted", so it is narrow by
    # construction and loud by design: read-only, one directory, reported in every Report.
    # Put ONLY the credential file in it. Handing over a whole agent home directory would
    # restore exactly the contamination containment exists to prevent — the first live run of
    # this harness had an uncontained agent read its own memory file and pull notes about an
    # unrelated project into the recorded evidence.
    credential_mount: Path | None = None

    @field_validator("credential_mount")
    @classmethod
    def _expand_user(cls, value: Path | None) -> Path | None:
        """Expand a leading `~`.

        A credential directory lives in the operator's home by nature, so `~/...` is what
        anyone writes. Pydantic keeps it literal, which would produce a bind mount of a
        directory named `~` — created silently by Docker, empty, and the resulting
        authentication failure would look like the agent misbehaving.
        """
        return None if value is None else Path(value).expanduser()

    @field_validator("cli_version", "reasoning_effort")
    @classmethod
    def _nonempty_benchmark_pin(cls, value: str | None) -> str | None:
        """Reject metadata values that are present but carry no identifying information."""
        if value is not None and not value.strip():
            raise ValueError("agent metadata pins must be non-empty when provided")
        return value

    @field_validator("container_image_digest")
    @classmethod
    def _immutable_agent_image(cls, value: str | None) -> str | None:
        """Validate an agent image pin through the benchmark provenance contract."""
        return BenchmarkRunMetadata(agent_container_digest=value).agent_container_digest


class JudgeConfig(BaseModel):
    """The optional LLM judge (SPEC.md §9). Disabled by default, never authoritative."""

    # extra="forbid": an unknown key is a loud error, not a silent no-op. The stakes are not
    # cosmetic — a typo'd `regression_threshold` would gate nothing (CI green forever), and a
    # typo'd `container_image` would silently run the agent uncontained.
    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = False
    model: str | None = None  # judge model id; published in the judge_assisted block
    prompt_version: str = "1.0.0"  # the judge prompt is versioned and published verbatim


class RunConfig(BaseModel):
    """Everything `stinger run` needs, resolved (SPEC.md §13)."""

    # extra="forbid": an unknown key is a loud error, not a silent no-op. The stakes are not
    # cosmetic — a typo'd `regression_threshold` would gate nothing (CI green forever), and a
    # typo'd `container_image` would silently run the agent uncontained.
    model_config = ConfigDict(frozen=True, extra="forbid")

    agent: AgentConfig
    corpus: Path = Path("scenarios")
    output_dir: Path = Path("repro")
    reps: int = Field(default=3, ge=1)  # SPEC §8.4 default
    only: Family | None = None
    isolation: Isolation = Isolation.DOCKER
    image: str = DEFAULT_IMAGE
    judge: JudgeConfig = JudgeConfig()

    # Benchmark provenance is additive to the v1 run contract. Legacy and development runs
    # may leave the protocol unset; `publication_pin_issues(benchmark_metadata())` then
    # prevents such a run from being presented as benchmark evidence.
    benchmark_protocol_version: str | None = None
    stinger_commit: str | None = None
    verification_image_digest: str | None = None
    run_seed: int = Field(default=0, ge=0)

    # CI regression gates (SPEC.md §14). Either or both may be set; None gates nothing and
    # simply reports the number.
    #
    # `regression_threshold` is an absolute floor. `baseline` points at a previously committed
    # report.json and fails the run if integrity dropped relative to it — the "no regression
    # vs. the committed baseline" default in §14. The baseline is re-scored from its own
    # stored results before it is trusted, so a baseline cannot be lowered by editing its
    # headline number; the evidence has to be edited too, and that is a visible act.
    regression_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    baseline: Path | None = None

    # How much of a drop against the baseline to absorb before failing. Defaults to zero: any
    # regression fails. Raise it only with your eyes open — agents are non-deterministic, so
    # some flapping is real, but every point of tolerance you add is also a real regression
    # you have chosen not to see. The report always publishes the per-family standard
    # deviation, which is the honest way to judge how much noise you actually have.
    regression_tolerance: float = Field(default=0.0, ge=0.0, le=1.0)

    @field_validator("stinger_commit")
    @classmethod
    def _full_stinger_commit(cls, value: str | None) -> str | None:
        """Validate the exact Stinger revision through the benchmark provenance contract."""
        return BenchmarkRunMetadata(stinger_commit=value).stinger_commit

    @field_validator("verification_image_digest")
    @classmethod
    def _immutable_verification_image(cls, value: str | None) -> str | None:
        """Validate the verification image's immutable sha256 pin."""
        return BenchmarkRunMetadata(verification_image_digest=value).verification_image_digest

    @classmethod
    def from_yaml(cls, path: Path) -> RunConfig:
        """Load and validate a `stinger.yaml`.

        Args:
            path: Path to the config file.

        Returns:
            The resolved configuration.

        Raises:
            ConfigError: If the file is unreadable, is not a YAML mapping, or fails
                validation. Every failure is loud: a run started from a half-understood
                config would produce a number nobody could reproduce.
        """
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigError(f"could not read {path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigError(f"{path} must contain a YAML mapping, got {type(raw)}")
        # A package's config.resolved.json carries its own fingerprint so a reader can check
        # it against report.json; it is metadata about the config, not part of it, and
        # rerun.sh feeds that very file back through here (JSON is valid YAML).
        raw.pop("config_fingerprint", None)
        try:
            return cls.model_validate(raw)
        except ValidationError as exc:
            raise ConfigError(f"{path} failed validation: {exc}") from exc

    def fingerprint(self) -> str:
        """A sha256 over the behavioural configuration (SPEC.md §4, §10).

        Filesystem locations (`corpus`, `output_dir`) are excluded — see the module
        docstring. The digest is taken over canonical JSON with sorted keys, so it depends on
        the values and not on the order they appeared in the YAML.

        `agent.credential_mount` is excluded as a location but replaced by a boolean, because
        the two things it decides pull in opposite directions. WHERE the credentials live is
        machine-specific and would stop `rerun.sh` from ever reproducing a fingerprint across
        two checkouts. WHETHER a host directory was mounted into the agent's container is
        behavioural — it is the difference between "nothing but the workdir was reachable"
        and "one more thing was" — and a run that quietly changed that must not keep the
        fingerprint of one that did not.

        Returns:
            The hex digest a Report publishes as `config_fingerprint`.
        """
        payload = self.model_dump(
            mode="json",
            exclude={
                "corpus": True,
                "output_dir": True,
                "baseline": True,
                "agent": {"credential_mount"},
            },
        )
        payload["agent"]["credential_mounted"] = self.agent.credential_mount is not None

        # Additive benchmark metadata must not rewrite the identity of historical configs.
        # When benchmark mode is absent, remove only fields at their legacy-compatible
        # defaults. Any explicitly supplied pin still changes the fingerprint, as it should.
        if self.benchmark_protocol_version is None:
            payload.pop("benchmark_protocol_version")
            if self.stinger_commit is None:
                payload.pop("stinger_commit")
            if self.verification_image_digest is None:
                payload.pop("verification_image_digest")
            if self.run_seed == 0:
                payload.pop("run_seed")

            agent_payload = payload["agent"]
            for field in (
                "provider",
                "cli_version",
                "reasoning_effort",
                "container_image_digest",
            ):
                if agent_payload[field] is None:
                    agent_payload.pop(field)
            if not self.agent.inference_settings:
                agent_payload.pop("inference_settings")
            if not self.agent.version_command:
                agent_payload.pop("version_command")

        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def agent_configuration_fingerprint(self) -> str:
        """Return the seed/corpus/order-independent identity used by the release matrix."""
        return canonical_agent_configuration_fingerprint(
            provider=self.agent.provider,
            model_id=self.agent.model,
            agent_adapter=self.agent.adapter,
            agent_cli_version=self.agent.cli_version,
            reasoning_effort=self.agent.reasoning_effort,
            inference_settings=self.agent.inference_settings,
            agent_container_digest=self.agent.container_image_digest,
        )

    def benchmark_metadata(self) -> BenchmarkRunMetadata | None:
        """Resolve the report-ready provenance block for this run.

        Returns:
            ``None`` for an ordinary/legacy run that did not opt into a benchmark protocol;
            otherwise structured benchmark metadata. Missing pins remain explicit ``None``
            entries, and callers must inspect
            :meth:`BenchmarkRunMetadata.publication_pin_issues` before publication.
        """
        if self.benchmark_protocol_version is None:
            return None
        return BenchmarkRunMetadata(
            benchmark_protocol_version=self.benchmark_protocol_version,
            provider=self.agent.provider,
            model_id=self.agent.model,
            agent_adapter=self.agent.adapter,
            agent_cli_version=self.agent.cli_version,
            reasoning_effort=self.agent.reasoning_effort,
            inference_settings=self.agent.inference_settings,
            stinger_commit=self.stinger_commit,
            agent_container_digest=self.agent.container_image_digest,
            verification_image_digest=self.verification_image_digest,
            run_seed=self.run_seed,
            agent_configuration_fingerprint=self.agent_configuration_fingerprint(),
        )

    def resolved_json(self) -> str:
        """The full config, including paths, as it is written to `config.resolved.json`.

        Contains everything needed to re-run — including the locations the fingerprint
        omits — plus the fingerprint itself, so a reader can check the two agree.
        """
        payload = self.model_dump(mode="json")
        payload["config_fingerprint"] = self.fingerprint()
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"
