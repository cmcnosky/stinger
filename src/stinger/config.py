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
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from stinger.harness.sandbox import DEFAULT_IMAGE, Isolation
from stinger.models import Family

__all__ = ["AgentConfig", "ConfigError", "JudgeConfig", "RunConfig"]


class ConfigError(Exception):
    """Raised when a `stinger.yaml` cannot be read as a RunConfig."""


class AgentConfig(BaseModel):
    """Which agent is under test, and how to drive it (SPEC.md §5)."""

    model_config = ConfigDict(frozen=True)

    adapter: str  # "claude-code" | "codex" | "aider" | "shell" | "recorded"
    model: str | None = None  # the agent's model id, when it has one; part of the fingerprint
    command: list[str] = []  # argv template for the generic `shell` adapter; needs "{prompt}"
    api_key_env: str | None = None  # NAME of the env var holding the key — never the key
    fixture: Path | None = None  # recorded-run fixture directory, for the `recorded` adapter
    options: dict[str, str] = {}  # extra environment for the agent process; in the fingerprint

    # Image to run the agent inside. SPEC.md §5 requires the agent have no access outside its
    # workdir, and only a container delivers that; without one the agent is a host subprocess
    # with its cwd set, which is weaker and is documented as such in adapters/cli_base.py. The
    # image must already contain the agent CLI, which is why Stinger cannot supply a default.
    container_image: str | None = None


class JudgeConfig(BaseModel):
    """The optional LLM judge (SPEC.md §9). Disabled by default, never authoritative."""

    model_config = ConfigDict(frozen=True)

    enabled: bool = False
    model: str | None = None  # judge model id; published in the judge_assisted block
    prompt_version: str = "1.0.0"  # the judge prompt is versioned and published verbatim


class RunConfig(BaseModel):
    """Everything `stinger run` needs, resolved (SPEC.md §13)."""

    model_config = ConfigDict(frozen=True)

    agent: AgentConfig
    corpus: Path = Path("scenarios")
    output_dir: Path = Path("repro")
    reps: int = Field(default=3, ge=1)  # SPEC §8.4 default
    only: Family | None = None
    isolation: Isolation = Isolation.DOCKER
    image: str = DEFAULT_IMAGE
    judge: JudgeConfig = JudgeConfig()

    # CI regression gate (SPEC.md §14). When set, `stinger run` exits non-zero if the overall
    # integrity rate falls below it. None means "report the number, gate nothing".
    regression_threshold: float | None = Field(default=None, ge=0.0, le=1.0)

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
        try:
            return cls.model_validate(raw)
        except ValidationError as exc:
            raise ConfigError(f"{path} failed validation: {exc}") from exc

    def fingerprint(self) -> str:
        """A sha256 over the behavioural configuration (SPEC.md §4, §10).

        Filesystem locations (`corpus`, `output_dir`) are excluded — see the module
        docstring. The digest is taken over canonical JSON with sorted keys, so it depends on
        the values and not on the order they appeared in the YAML.

        Returns:
            The hex digest a Report publishes as `config_fingerprint`.
        """
        payload = self.model_dump(mode="json", exclude={"corpus", "output_dir"})
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def resolved_json(self) -> str:
        """The full config, including paths, as it is written to `config.resolved.json`.

        Contains everything needed to re-run — including the locations the fingerprint
        omits — plus the fingerprint itself, so a reader can check the two agree.
        """
        payload = self.model_dump(mode="json")
        payload["config_fingerprint"] = self.fingerprint()
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"
