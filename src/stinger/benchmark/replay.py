"""Offline reconstruction of benchmark classifications from escrow evidence.

An Integrity Report is a useful index, not primary evidence.  For an ordinary development
run, :func:`stinger.report.generate.verify_report` checks that the numbers and outcomes are
internally consistent with the fields stored in ``report.json``.  A sealed benchmark needs a
stronger boundary: the public report and the private escrow report are the same bytes, and
every classification-relevant field in those bytes is reconstructed here from the exact
sealed scenario plus the per-run escrow artifacts.

The runner persists one ``classification.replay.json`` beside each transcript.  It contains
only observations that cannot be reconstructed from the retained filesystem:

* the parsed agent-authored fields and command log, bound to ``transcript.txt`` by hash; and
* the exact completion-check and suite-rerun command observations.

It deliberately does *not* contain ``goal_met``, ``agent_claimed_done``, refusal,
``detector_results``, ``run_error``, or ``outcome``.  Those are derived again below using the
same pure detector functions and frozen classifier as the live runner.  The before snapshot
is rebuilt from the sealed scenario and the after snapshot is captured from the retained
final workdir.

Benchmark verification also re-executes the held-out check and suite in the pinned,
network-disabled verification image.  The stored observations remain the source for exact
human-readable detector evidence (pytest output contains incidental timing), while the
fresh execution must agree on every observation a detector semantically consumes.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from stinger.adapters.base import AgentRun
from stinger.adapters.cli_base import CliAgentAdapter
from stinger.adapters.factory import AdapterError, build_adapter
from stinger.benchmark.git_checkout import (
    GitCheckoutError,
    verify_loaded_stinger_implementation,
)
from stinger.benchmark.protocol import (
    BenchmarkRuntimeProvenance,
    canonical_local_provider_binding_issues,
    publication_pin_issues,
)
from stinger.config import RunConfig
from stinger.detectors.base import DetectorContext, RepoState, Verification
from stinger.docker_runtime import (
    DOCKER_RUNTIME_CLAIM_BOUNDARY,
    DockerRuntimeError,
    DockerRuntimeIdentity,
    verify_docker_runtime,
)
from stinger.harness.sandbox import Isolation, Sandbox, capture, diff_states
from stinger.models import ExecResult, Report, ScenarioResult
from stinger.scenario.loader import Scenario, ScenarioLoadError, discover_scenarios

REPLAY_FORMAT_VERSION: Final = "1"
REPLAY_RECORD_NAME: Final = "classification.replay.json"
INVOCATION_RECEIPT_FORMAT_VERSION: Final = "1"
INVOCATION_RECEIPT_NAME: Final = "invocation.receipt.json"
INVOCATION_CHALLENGE_FORMAT_VERSION: Final = "1"
INVOCATION_CHALLENGE_NAME: Final = "invocation.challenge.json"
INVOCATION_AGGREGATE_FORMAT_VERSION: Final = "1"
INVOCATION_AGGREGATE_NAME: Final = "invocation.aggregate.json"
REPRO_EVIDENCE_FORMAT_VERSION: Final = "3"
REPRO_EVIDENCE_FORMAT_FILE: Final = "repro.format.version"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PYTEST_TIME_RE = re.compile(r"(?<=\bin )\d+(?:\.\d+)?s\b")


class ClassificationReplayError(Exception):
    """Raised when escrow artifacts cannot reproduce one reported classification."""


class AgentRunObservation(BaseModel):
    """Agent fields retained for replay, with transcript bytes stored only once."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    transcript_sha256: str
    final_message: str
    authored_text: str | None = None
    commands: tuple[str, ...] = ()
    commands_observed: bool = False
    exit_ok: bool = True
    error: str | None = None

    @field_validator("transcript_sha256")
    @classmethod
    def _valid_transcript_digest(cls, value: str) -> str:
        if _SHA256_RE.fullmatch(value) is None:
            raise ValueError("transcript_sha256 must be a lowercase sha256 digest")
        return value

    @field_validator("error")
    @classmethod
    def _nonblank_error(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("agent error must be absent or nonblank")
        return value

    @classmethod
    def from_run(cls, run: AgentRun) -> AgentRunObservation:
        """Snapshot the parsed agent observation without duplicating its transcript."""
        return cls(
            transcript_sha256=_sha256(run.transcript.encode("utf-8")),
            final_message=run.final_message,
            authored_text=run.authored_text,
            commands=tuple(run.commands),
            commands_observed=run.commands_observed,
            exit_ok=run.exit_ok,
            error=run.error,
        )

    def materialize(self, transcript: str) -> AgentRun:
        """Rebuild the detector input after checking the exact transcript bytes."""
        if _sha256(transcript.encode("utf-8")) != self.transcript_sha256:
            raise ClassificationReplayError(
                "classification replay transcript hash disagrees with transcript.txt"
            )
        return AgentRun(
            transcript=transcript,
            final_message=self.final_message,
            authored_text=self.authored_text,
            commands=list(self.commands),
            commands_observed=self.commands_observed,
            exit_ok=self.exit_ok,
            error=self.error,
        )


class ReplayExecObservation(BaseModel):
    """Closed-schema command observation retained as classification evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    argv: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @classmethod
    def from_exec_result(cls, result: ExecResult) -> ReplayExecObservation:
        """Snapshot an execution result without inheriting its permissive public schema."""
        return cls(
            argv=tuple(result.argv),
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=result.timed_out,
        )

    def materialize(self) -> ExecResult:
        """Rebuild the detector input after closed-schema validation."""
        return ExecResult(
            argv=list(self.argv),
            exit_code=self.exit_code,
            stdout=self.stdout,
            stderr=self.stderr,
            timed_out=self.timed_out,
        )


class ClassificationReplayRecord(BaseModel):
    """Primary observations needed to reconstruct one ScenarioResult."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: str = REPLAY_FORMAT_VERSION
    scenario_id: str
    repetition: int
    agent_run: AgentRunObservation
    completion: ReplayExecObservation | None
    suite_rerun: ReplayExecObservation | None

    @field_validator("scenario_id")
    @classmethod
    def _nonblank_scenario_id(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError("scenario_id must be nonblank and canonical")
        return value

    @field_validator("repetition")
    @classmethod
    def _nonnegative_repetition(cls, value: int) -> int:
        if value < 0:
            raise ValueError("repetition must be nonnegative")
        return value


class InvocationContext(BaseModel):
    """Deterministic execution-plan identity supplied to one runner invocation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_plan_id: str
    invocation_id: str
    ordinal: int
    scenario_id: str
    repetition: int
    config_fingerprint: str
    runtime_provenance_sha256: str
    agent_adapter: str

    @field_validator(
        "run_plan_id",
        "invocation_id",
        "config_fingerprint",
        "runtime_provenance_sha256",
    )
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        if _SHA256_RE.fullmatch(value) is None:
            raise ValueError("invocation context digests must be lowercase sha256 values")
        return value

    @field_validator("ordinal")
    @classmethod
    def _positive_ordinal(cls, value: int) -> int:
        if value < 1:
            raise ValueError("invocation ordinal must be positive")
        return value

    @field_validator("scenario_id", "agent_adapter")
    @classmethod
    def _nonblank_identifier(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError("invocation identifiers must be nonblank and canonical")
        return value

    @field_validator("repetition")
    @classmethod
    def _nonnegative_invocation_repetition(cls, value: int) -> int:
        if value < 0:
            raise ValueError("invocation repetition must be nonnegative")
        return value


class InvocationReceipt(BaseModel):
    """Primary per-process event binding one planned invocation to its exact evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: str = INVOCATION_RECEIPT_FORMAT_VERSION
    run_plan_id: str
    invocation_id: str
    ordinal: int
    scenario_id: str
    repetition: int
    config_fingerprint: str
    runtime_provenance_sha256: str
    agent_adapter: str
    invocation_challenge_sha256: str
    invocation_challenge_nonce_sha256: str
    provider_response_id_sha256: str | None = None
    transcript_sha256: str
    replay_record_sha256: str
    before_diff_sha256: str
    after_diff_sha256: str
    final_worktree_sha256: str
    result_sha256: str
    execution_evidence_sha256: str

    @field_validator(
        "run_plan_id",
        "invocation_id",
        "config_fingerprint",
        "runtime_provenance_sha256",
        "invocation_challenge_sha256",
        "invocation_challenge_nonce_sha256",
        "provider_response_id_sha256",
        "transcript_sha256",
        "replay_record_sha256",
        "before_diff_sha256",
        "after_diff_sha256",
        "final_worktree_sha256",
        "result_sha256",
        "execution_evidence_sha256",
    )
    @classmethod
    def _valid_receipt_digest(cls, value: str | None) -> str | None:
        if value is not None and _SHA256_RE.fullmatch(value) is None:
            raise ValueError("invocation receipt digests must be lowercase sha256 values")
        return value

    @field_validator("ordinal")
    @classmethod
    def _positive_receipt_ordinal(cls, value: int) -> int:
        if value < 1:
            raise ValueError("invocation receipt ordinal must be positive")
        return value

    @field_validator("scenario_id", "agent_adapter")
    @classmethod
    def _nonblank_receipt_identifier(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError("invocation receipt identifiers must be nonblank and canonical")
        return value

    @field_validator("repetition")
    @classmethod
    def _nonnegative_receipt_repetition(cls, value: int) -> int:
        if value < 0:
            raise ValueError("invocation receipt repetition must be nonnegative")
        return value


class InvocationChallenge(BaseModel):
    """Pre-invocation runner event whose nonce never enters scoring or the prompt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: str = INVOCATION_CHALLENGE_FORMAT_VERSION
    run_plan_id: str
    invocation_id: str
    ordinal: int
    scenario_id: str
    repetition: int
    nonce_hex: str

    @field_validator("run_plan_id", "invocation_id")
    @classmethod
    def _valid_challenge_digest(cls, value: str) -> str:
        if _SHA256_RE.fullmatch(value) is None:
            raise ValueError("invocation challenge ids must be lowercase sha256 values")
        return value

    @field_validator("nonce_hex")
    @classmethod
    def _valid_challenge_nonce(cls, value: str) -> str:
        if _SHA256_RE.fullmatch(value) is None:
            raise ValueError("invocation challenge nonce must be 32 random bytes as hex")
        return value

    @field_validator("ordinal")
    @classmethod
    def _positive_challenge_ordinal(cls, value: int) -> int:
        if value < 1:
            raise ValueError("invocation challenge ordinal must be positive")
        return value

    @field_validator("scenario_id")
    @classmethod
    def _nonblank_challenge_scenario(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError("invocation challenge scenario id must be canonical")
        return value

    @field_validator("repetition")
    @classmethod
    def _nonnegative_challenge_repetition(cls, value: int) -> int:
        if value < 0:
            raise ValueError("invocation challenge repetition must be nonnegative")
        return value


class InvocationAggregate(BaseModel):
    """Canonical run-level receipt suitable for an external workflow signature."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: str = INVOCATION_AGGREGATE_FORMAT_VERSION
    run_plan_id: str
    config_fingerprint: str
    runtime_provenance_sha256: str
    report_sha256: str
    replay_record_aggregate_sha256: str
    invocation_receipt_aggregate_sha256: str
    receipt_count: int
    invocation_ids: tuple[str, ...]
    invocation_challenge_nonce_sha256s: tuple[str, ...]
    provider_response_id_sha256s: tuple[str, ...]
    execution_evidence_sha256s: tuple[str, ...]

    @field_validator(
        "run_plan_id",
        "config_fingerprint",
        "runtime_provenance_sha256",
        "report_sha256",
        "replay_record_aggregate_sha256",
        "invocation_receipt_aggregate_sha256",
    )
    @classmethod
    def _valid_aggregate_digest(cls, value: str) -> str:
        if _SHA256_RE.fullmatch(value) is None:
            raise ValueError("invocation aggregate digests must be lowercase sha256 values")
        return value

    @field_validator(
        "invocation_ids",
        "invocation_challenge_nonce_sha256s",
        "provider_response_id_sha256s",
        "execution_evidence_sha256s",
    )
    @classmethod
    def _valid_aggregate_digest_sequence(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(_SHA256_RE.fullmatch(value) is None for value in values):
            raise ValueError("invocation aggregate sequences must contain sha256 values")
        return values

    @field_validator("receipt_count")
    @classmethod
    def _positive_receipt_count(cls, value: int) -> int:
        if value < 1:
            raise ValueError("invocation aggregate must contain at least one receipt")
        return value


@dataclass(frozen=True, slots=True)
class VerifiedInvocationReceipt:
    """One invocation receipt parsed and hashed from the same exact byte snapshot."""

    receipt: InvocationReceipt
    canonical_bytes: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedInvocationAggregate:
    """One invocation aggregate verified, parsed, and hashed from one exact snapshot."""

    aggregate: InvocationAggregate
    canonical_bytes: bytes
    sha256: str


def build_invocation_plan(
    *,
    config: RunConfig,
    corpus_hash: str,
    runtime_provenance: BenchmarkRuntimeProvenance,
    ordered_scenario_ids: Sequence[str],
) -> tuple[InvocationContext, ...]:
    """Derive deterministic per-row identities from the immutable execution plan."""
    if _SHA256_RE.fullmatch(corpus_hash) is None:
        raise ValueError("invocation plan corpus_hash must be a lowercase sha256 digest")
    if not ordered_scenario_ids or any(not item.strip() for item in ordered_scenario_ids):
        raise ValueError("invocation plan requires canonical ordered scenario ids")
    rows = tuple(
        (scenario_id, repetition)
        for scenario_id in ordered_scenario_ids
        for repetition in range(config.reps)
    )
    runtime_digest = benchmark_runtime_provenance_sha256(runtime_provenance)
    plan_payload = {
        "format_version": INVOCATION_RECEIPT_FORMAT_VERSION,
        "benchmark_protocol_version": config.benchmark_protocol_version,
        "stinger_commit": config.stinger_commit,
        "config_fingerprint": config.fingerprint(),
        "corpus_hash": corpus_hash,
        "run_seed": config.run_seed,
        "runtime_provenance_sha256": runtime_digest,
        "rows": [
            {"scenario_id": scenario_id, "repetition": repetition}
            for scenario_id, repetition in rows
        ],
    }
    run_plan_id = _sha256(_canonical_json(plan_payload))
    contexts: list[InvocationContext] = []
    for ordinal, (scenario_id, repetition) in enumerate(rows, start=1):
        invocation_id = _sha256(
            _canonical_json(
                {
                    "run_plan_id": run_plan_id,
                    "ordinal": ordinal,
                    "scenario_id": scenario_id,
                    "repetition": repetition,
                }
            )
        )
        contexts.append(
            InvocationContext(
                run_plan_id=run_plan_id,
                invocation_id=invocation_id,
                ordinal=ordinal,
                scenario_id=scenario_id,
                repetition=repetition,
                config_fingerprint=config.fingerprint(),
                runtime_provenance_sha256=runtime_digest,
                agent_adapter=config.agent.adapter,
            )
        )
    return tuple(contexts)


def write_classification_replay_record(
    artifacts_dir: Path,
    *,
    scenario_id: str,
    repetition: int,
    run: AgentRun,
    completion: ExecResult | None,
    suite_rerun: ExecResult | None,
) -> Path:
    """Atomically persist one canonical observation-only replay record.

    The target is new for every repetition.  Refusing to overwrite prevents a resumed or
    spliced run from silently replacing the observations that produced an existing report.
    """
    record = ClassificationReplayRecord(
        scenario_id=scenario_id,
        repetition=repetition,
        agent_run=AgentRunObservation.from_run(run),
        completion=(
            None if completion is None else ReplayExecObservation.from_exec_result(completion)
        ),
        suite_rerun=(
            None if suite_rerun is None else ReplayExecObservation.from_exec_result(suite_rerun)
        ),
    )
    target = artifacts_dir / REPLAY_RECORD_NAME
    if target.exists() or target.is_symlink():
        raise OSError("classification replay record already exists")
    content = _canonical_record_bytes(record)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{REPLAY_RECORD_NAME}.",
        dir=artifacts_dir,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return target


def load_classification_replay_record(path: Path) -> ClassificationReplayRecord:
    """Load one exact, canonical, regular replay record."""
    encoded = _read_regular(path, "classification replay record")
    try:
        record = ClassificationReplayRecord.model_validate_json(encoded)
    except ValidationError:
        raise ClassificationReplayError(
            "classification replay record failed closed schema validation"
        ) from None
    if record.format_version != REPLAY_FORMAT_VERSION:
        raise ClassificationReplayError(
            f"classification replay format {record.format_version!r} is unsupported"
        )
    if encoded != _canonical_record_bytes(record):
        raise ClassificationReplayError(
            "classification replay record is not canonical deterministic JSON"
        )
    return record


def write_invocation_challenge(
    artifacts_dir: Path,
    *,
    context: InvocationContext,
) -> Path:
    """Persist a cryptographic evidence-only event immediately before adapter invocation."""
    challenge = InvocationChallenge(
        run_plan_id=context.run_plan_id,
        invocation_id=context.invocation_id,
        ordinal=context.ordinal,
        scenario_id=context.scenario_id,
        repetition=context.repetition,
        nonce_hex=secrets.token_hex(32),
    )
    target = artifacts_dir / INVOCATION_CHALLENGE_NAME
    _atomic_create(target, _canonical_model_bytes(challenge), label="invocation challenge")
    return target


def load_invocation_challenge(path: Path) -> InvocationChallenge:
    """Load one exact canonical pre-invocation runner challenge."""
    encoded = _read_regular(path, "invocation challenge")
    try:
        challenge = InvocationChallenge.model_validate_json(encoded)
    except ValidationError:
        raise ClassificationReplayError(
            "invocation challenge failed closed schema validation"
        ) from None
    if challenge.format_version != INVOCATION_CHALLENGE_FORMAT_VERSION:
        raise ClassificationReplayError("invocation challenge format is unsupported")
    if encoded != _canonical_model_bytes(challenge):
        raise ClassificationReplayError("invocation challenge is not canonical deterministic JSON")
    return challenge


def write_invocation_receipt(
    artifacts_dir: Path,
    *,
    context: InvocationContext,
    transcript: str,
    final_worktree: RepoState,
    result: ScenarioResult,
) -> Path:
    """Persist one canonical event receipt after classification is complete."""
    if context.scenario_id != result.scenario_id or context.repetition != result.repetition:
        raise OSError("invocation context disagrees with the completed result")
    challenge_path = artifacts_dir / INVOCATION_CHALLENGE_NAME
    try:
        challenge = load_invocation_challenge(challenge_path)
    except ClassificationReplayError:
        raise OSError("invocation challenge is unavailable for receipt construction") from None
    _require_challenge_context(challenge, context)
    challenge_bytes = _read_regular_for_write(challenge_path, "invocation challenge")
    replay_bytes = _read_regular_for_write(
        artifacts_dir / REPLAY_RECORD_NAME,
        "classification replay record",
    )
    transcript_bytes = _read_regular_for_write(
        artifacts_dir / "transcript.txt",
        "invocation transcript",
    )
    if transcript_bytes != transcript.encode("utf-8"):
        raise OSError("invocation transcript changed before receipt construction")
    before_diff = _read_regular_for_write(artifacts_dir / "before.diff", "before diff")
    after_diff = _read_regular_for_write(artifacts_dir / "after.diff", "after diff")
    provider_response_id_sha256 = _provider_response_id_sha256(
        context.agent_adapter,
        transcript,
    )
    core = {
        "scenario_id": result.scenario_id,
        "repetition": result.repetition,
        "config_fingerprint": context.config_fingerprint,
        "runtime_provenance_sha256": context.runtime_provenance_sha256,
        "agent_adapter": context.agent_adapter,
        "invocation_challenge_sha256": _sha256(challenge_bytes),
        "invocation_challenge_nonce_sha256": _challenge_nonce_sha256(challenge),
        "provider_response_id_sha256": provider_response_id_sha256,
        "transcript_sha256": _sha256(transcript_bytes),
        "replay_record_sha256": _sha256(replay_bytes),
        "before_diff_sha256": _sha256(before_diff),
        "after_diff_sha256": _sha256(after_diff),
        "final_worktree_sha256": repo_state_sha256(final_worktree),
        "result_sha256": scenario_result_sha256(result),
    }
    receipt = InvocationReceipt.model_validate(
        {
            "run_plan_id": context.run_plan_id,
            "invocation_id": context.invocation_id,
            "ordinal": context.ordinal,
            **core,
            "execution_evidence_sha256": _sha256(_canonical_json(core)),
        }
    )
    target = artifacts_dir / INVOCATION_RECEIPT_NAME
    _atomic_create(target, _canonical_model_bytes(receipt), label="invocation receipt")
    return target


def load_invocation_receipt(path: Path) -> InvocationReceipt:
    """Load one exact canonical invocation receipt."""
    return load_invocation_receipt_snapshot(path).receipt


def load_invocation_receipt_snapshot(path: Path) -> VerifiedInvocationReceipt:
    """Load, parse, and hash one invocation receipt from a single exact read."""
    encoded = _read_regular(path, "invocation receipt")
    try:
        receipt = InvocationReceipt.model_validate_json(encoded)
    except ValidationError:
        raise ClassificationReplayError(
            "invocation receipt failed closed schema validation"
        ) from None
    if receipt.format_version != INVOCATION_RECEIPT_FORMAT_VERSION:
        raise ClassificationReplayError("invocation receipt format is unsupported")
    if encoded != _canonical_model_bytes(receipt):
        raise ClassificationReplayError("invocation receipt is not canonical deterministic JSON")
    return VerifiedInvocationReceipt(
        receipt=receipt,
        canonical_bytes=encoded,
        sha256=_sha256(encoded),
    )


def write_invocation_aggregate(
    package: Path,
    *,
    config: RunConfig,
    report: Report,
) -> Path:
    """Validate every primary invocation receipt and atomically bind the run."""
    aggregate = build_invocation_aggregate(package, config=config, report=report)
    target = package / INVOCATION_AGGREGATE_NAME
    _atomic_create(target, _canonical_model_bytes(aggregate), label="invocation aggregate")
    return target


def build_invocation_aggregate(
    package: Path,
    *,
    config: RunConfig,
    report: Report,
) -> InvocationAggregate:
    """Recompute run-plan, receipt, and clone-resistance commitments from exact artifacts."""
    runtime = report.benchmark_runtime_provenance
    if runtime is None:
        raise ClassificationReplayError(
            "benchmark invocation aggregate requires runtime provenance"
        )
    ordered_scenario_ids = _ordered_scenario_ids(report)
    expected_contexts = build_invocation_plan(
        config=config,
        corpus_hash=report.corpus_hash,
        runtime_provenance=runtime,
        ordered_scenario_ids=ordered_scenario_ids,
    )
    expected_by_row = {
        (context.scenario_id, context.repetition): context for context in expected_contexts
    }
    if len(expected_by_row) != len(report.results):
        raise ClassificationReplayError(
            "benchmark invocation plan does not exactly cover report rows"
        )

    receipt_entries: list[dict[str, object]] = []
    replay_entries: list[dict[str, object]] = []
    receipts: list[InvocationReceipt] = []
    for result in report.results:
        row = (result.scenario_id, result.repetition)
        context = expected_by_row.get(row)
        if context is None:
            raise ClassificationReplayError(
                "benchmark invocation receipt row is outside the deterministic plan"
            )
        run_dir = package / "runs" / result.scenario_id / str(result.repetition)
        receipt_path = run_dir / INVOCATION_RECEIPT_NAME
        verified_receipt = load_invocation_receipt_snapshot(receipt_path)
        receipt = verified_receipt.receipt
        _verify_invocation_receipt(
            receipt,
            context=context,
            run_dir=run_dir,
            result=result,
        )
        replay_bytes = _read_regular(
            run_dir / REPLAY_RECORD_NAME,
            "classification replay record",
        )
        receipts.append(receipt)
        receipt_entries.append(
            {
                "invocation_id": receipt.invocation_id,
                "receipt_sha256": verified_receipt.sha256,
            }
        )
        replay_entries.append(
            {
                "invocation_id": receipt.invocation_id,
                "replay_record_sha256": _sha256(replay_bytes),
            }
        )

    _require_unique_invocations(receipts, agent_adapter=config.agent.adapter)
    first = receipts[0]
    return InvocationAggregate(
        run_plan_id=first.run_plan_id,
        config_fingerprint=config.fingerprint(),
        runtime_provenance_sha256=benchmark_runtime_provenance_sha256(runtime),
        report_sha256=_sha256(_canonical_json(report.model_dump(mode="json"))),
        replay_record_aggregate_sha256=_sha256(_canonical_json({"replay_records": replay_entries})),
        invocation_receipt_aggregate_sha256=_sha256(
            _canonical_json({"invocation_receipts": receipt_entries})
        ),
        receipt_count=len(receipts),
        invocation_ids=tuple(receipt.invocation_id for receipt in receipts),
        invocation_challenge_nonce_sha256s=tuple(
            receipt.invocation_challenge_nonce_sha256 for receipt in receipts
        ),
        provider_response_id_sha256s=tuple(
            receipt.provider_response_id_sha256
            for receipt in receipts
            if receipt.provider_response_id_sha256 is not None
        ),
        execution_evidence_sha256s=tuple(receipt.execution_evidence_sha256 for receipt in receipts),
    )


def load_invocation_aggregate(path: Path) -> InvocationAggregate:
    """Load one exact canonical run-level invocation aggregate."""
    return load_invocation_aggregate_snapshot(path).aggregate


def load_invocation_aggregate_snapshot(path: Path) -> VerifiedInvocationAggregate:
    """Load, parse, and hash one invocation aggregate from a single exact read."""
    encoded = _read_regular(path, "invocation aggregate")
    try:
        aggregate = InvocationAggregate.model_validate_json(encoded)
    except ValidationError:
        raise ClassificationReplayError(
            "invocation aggregate failed closed schema validation"
        ) from None
    if aggregate.format_version != INVOCATION_AGGREGATE_FORMAT_VERSION:
        raise ClassificationReplayError("invocation aggregate format is unsupported")
    if encoded != _canonical_model_bytes(aggregate):
        raise ClassificationReplayError("invocation aggregate is not canonical deterministic JSON")
    return VerifiedInvocationAggregate(
        aggregate=aggregate,
        canonical_bytes=encoded,
        sha256=_sha256(encoded),
    )


def verify_invocation_aggregate(
    package: Path,
    *,
    config: RunConfig,
    report: Report,
) -> str:
    """Rebuild and compare the signed-workflow-ready invocation aggregate."""
    return verify_invocation_aggregate_snapshot(
        package,
        config=config,
        report=report,
    ).sha256


def verify_invocation_aggregate_snapshot(
    package: Path,
    *,
    config: RunConfig,
    report: Report,
) -> VerifiedInvocationAggregate:
    """Verify and retain one aggregate object, byte snapshot, and hash together."""
    stored = load_invocation_aggregate_snapshot(package / INVOCATION_AGGREGATE_NAME)
    rebuilt = build_invocation_aggregate(package, config=config, report=report)
    if stored.aggregate != rebuilt:
        raise ClassificationReplayError("invocation aggregate disagrees with exact run artifacts")
    return stored


def verify_report_classifications_from_escrow(
    sealed_corpus: Path,
    rerunnable_evidence: Path,
    *,
    config: RunConfig,
    report: Report,
) -> str:
    """Reconstruct every report row from exact escrow artifacts and fresh verification.

    Args:
        sealed_corpus: Inventory-bound snapshot of the complete sealed corpus.
        rerunnable_evidence: Inventory-bound snapshot of the complete repro package.
        config: Exact verified run configuration.
        report: Exact public/escrow report.

    Returns:
        A canonical aggregate digest of every replay record and reconstructed result.

    Raises:
        ClassificationReplayError: On any missing artifact, mismatch, unpinned execution,
            or classification disagreement.
    """
    format_path = rerunnable_evidence / REPRO_EVIDENCE_FORMAT_FILE
    if _read_regular(format_path, "repro evidence format") != (
        REPRO_EVIDENCE_FORMAT_VERSION + "\n"
    ).encode("ascii"):
        raise ClassificationReplayError(
            "benchmark repro package does not use the required classification-replay format"
        )

    invocation_aggregate_sha256 = verify_invocation_aggregate(
        rerunnable_evidence,
        config=config,
        report=report,
    )

    try:
        scenarios = discover_scenarios(sealed_corpus)
    except ScenarioLoadError:
        raise ClassificationReplayError(
            "sealed scenario inventory could not be loaded for classification replay"
        ) from None
    by_id = {scenario.id: scenario for scenario in scenarios}
    if set(by_id) != {result.scenario_id for result in report.results}:
        raise ClassificationReplayError(
            "classification replay scenario set disagrees with the sealed report"
        )

    # The same immutable verification image serves all rows.  Preflight and identity checks
    # happen once, before any scenario-derived code executes.
    try:
        repository = Path(__file__).resolve().parents[3]
        sandbox = Sandbox(isolation=Isolation.DOCKER, image=config.image)
        sandbox.preflight_benchmark(repository)
        _verify_replay_runtime(
            config,
            report,
            docker_runtime_identity=sandbox.docker_runtime_identity,
            verification_image_identity=sandbox.verification_image_identity,
            verification_image_policy_sha256=(sandbox.verification_image_policy_sha256),
        )
        adapter = _replay_adapter(config)
    except ClassificationReplayError:
        raise
    except Exception:
        raise ClassificationReplayError(
            "classification replay runtime could not be established"
        ) from None

    inventory: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="stinger-classification-replay-") as temporary_name:
        workspace = Path(temporary_name)
        for ordinal, result in enumerate(
            sorted(
                report.results,
                key=lambda item: (item.scenario_id, item.repetition),
            ),
            start=1,
        ):
            scenario = by_id[result.scenario_id]
            try:
                record, reconstructed = _reconstruct_result(
                    scenario,
                    result,
                    rerunnable_evidence,
                    sandbox=sandbox,
                    adapter=adapter,
                    workspace=workspace,
                    ordinal=ordinal,
                )
                _compare_result(result, reconstructed, ordinal=ordinal)
            except ClassificationReplayError:
                raise
            except Exception:
                # This is a private evidence trust boundary. Adapter parsers, detector
                # implementations, and filesystem reconstruction must all fail closed
                # without reflecting attacker-controlled transcript or sealed-corpus
                # details into diagnostics.
                raise ClassificationReplayError(
                    f"result ordinal {ordinal}: private replay artifacts could not be reconstructed"
                ) from None
            inventory.append(
                {
                    "scenario_id": result.scenario_id,
                    "repetition": result.repetition,
                    "record_sha256": _sha256(_canonical_record_bytes(record)),
                    "classification_sha256": _sha256(
                        _canonical_json(_classification_payload(reconstructed))
                    ),
                }
            )
    try:
        sandbox.verify_runtime_unchanged()
    except Exception:
        raise ClassificationReplayError(
            "classification replay Docker runtime changed during reconstruction"
        ) from None
    return _sha256(
        _canonical_json(
            {
                "classification_replays": inventory,
                "invocation_aggregate_sha256": invocation_aggregate_sha256,
            }
        )
    )


def _reconstruct_result(
    scenario: Scenario,
    reported: ScenarioResult,
    package: Path,
    *,
    sandbox: Sandbox,
    adapter: CliAgentAdapter,
    workspace: Path,
    ordinal: int,
) -> tuple[ClassificationReplayRecord, ScenarioResult]:
    """Rebuild one classification and independently replay its verification commands."""
    # Imported lazily: runner imports the record writer, so a module-level import would
    # create a cycle.
    from stinger.harness.runner import (
        _adapter_evidence,
        _evaluate_detectors,
        _goal_met,
        agent_refused,
        classify,
        parse_claim,
    )

    manifest = scenario.manifest
    run_dir = package / "runs" / scenario.id / str(reported.repetition)
    record = load_classification_replay_record(run_dir / REPLAY_RECORD_NAME)
    if record.scenario_id != scenario.id or record.repetition != reported.repetition:
        raise ClassificationReplayError(
            f"result ordinal {ordinal}: replay identity disagrees with its inventory position"
        )

    transcript_bytes = _read_regular(run_dir / "transcript.txt", "replay transcript")
    try:
        transcript = transcript_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ClassificationReplayError("replay transcript is not valid UTF-8") from exc
    run = record.agent_run.materialize(transcript)
    # At Protocol 2's zero-ERROR publication threshold, every accepted agent invocation
    # exited successfully. Re-run the configured adapter's deterministic parser over the
    # exact transcript, so final_message/authored_text/commands are parser-derived evidence
    # rather than caller-authored fields in the replay record.
    parsed = adapter.replay(transcript, exit_code=0)
    if AgentRunObservation.from_run(parsed) != record.agent_run:
        raise ClassificationReplayError(
            "stored agent observation disagrees with deterministic adapter replay"
        )
    if run.error is not None or not run.exit_ok:
        raise ClassificationReplayError(
            "benchmark classification replay refuses an errored agent invocation"
        )

    before_dir = workspace / "before" / scenario.id / str(reported.repetition)
    before = sandbox.prepare(scenario.directory, manifest, before_dir)
    before_state = capture(before)
    after_dir = run_dir / "workdir"
    after_state = capture(after_dir)

    seed_state = capture(scenario.directory / manifest.seed_repo)
    _require_text_equals(
        run_dir / "before.diff",
        diff_states(seed_state, before_state),
        "before.diff",
    )
    _require_text_equals(
        run_dir / "after.diff",
        diff_states(before_state, after_state),
        "after.diff",
    )

    completion = None if record.completion is None else record.completion.materialize()
    suite_rerun = None if record.suite_rerun is None else record.suite_rerun.materialize()
    claimed = parse_claim(run.final_message)
    goal_met = _goal_met(manifest, completion)
    verification = Verification(
        completion=completion,
        suite_rerun=suite_rerun,
        goal_met=goal_met,
        agent_claimed_done=claimed,
    )
    context = DetectorContext(
        before=before_state,
        after=after_state,
        run=run,
        manifest=manifest,
        verification=verification,
    )
    detector_results = _adapter_evidence(run) + _evaluate_detectors(manifest, context)
    refused = agent_refused(run.final_message, manifest)
    outcome = classify(detector_results, goal_met, claimed, run, refused)

    fresh_dir = workspace / "fresh-verification" / scenario.id / str(reported.repetition)
    fresh_dir.mkdir(parents=True)
    fresh_completion, fresh_suite = _fresh_verification_observations(
        scenario,
        after_dir,
        sandbox,
        fresh_dir,
    )
    _compare_exec_observation(
        completion,
        fresh_completion,
        label=f"result ordinal {ordinal} completion",
        consumer="completion",
    )
    _compare_exec_observation(
        suite_rerun,
        fresh_suite,
        label=f"result ordinal {ordinal} suite rerun",
        consumer="suite_rerun",
    )

    canonical_transcript_path = f"runs/{scenario.id}/{reported.repetition}/transcript.txt"
    canonical_diff_path = f"runs/{scenario.id}/{reported.repetition}/after.diff"
    return record, ScenarioResult(
        scenario_id=scenario.id,
        family=manifest.family,
        outcome=outcome,
        detector_results=detector_results,
        goal_met=goal_met,
        agent_claimed_done=claimed,
        transcript_path=canonical_transcript_path,
        diff_path=canonical_diff_path,
        # Observational duration never enters classification and cannot be replayed.
        duration_s=reported.duration_s,
        repetition=reported.repetition,
        run_error=run.error,
        benchmark_split=manifest.benchmark_split,
        scenario_version=manifest.scenario_version,
        cluster_id=manifest.cluster_id,
    )


def _replay_adapter(config: RunConfig) -> CliAgentAdapter:
    """Build the exact configured parser and reject adapters without replay semantics."""
    try:
        adapter = build_adapter(config.agent)
    except AdapterError as exc:
        raise ClassificationReplayError(
            "configured benchmark adapter could not be reconstructed"
        ) from exc
    if not isinstance(adapter, CliAgentAdapter):
        raise ClassificationReplayError(
            "configured benchmark adapter has no deterministic transcript replay contract"
        )
    return adapter


def _fresh_verification_observations(
    scenario: Scenario,
    final_workdir: Path,
    sandbox: Sandbox,
    artifacts_dir: Path,
) -> tuple[ExecResult | None, ExecResult | None]:
    """Re-execute both network-disabled verifier channels from the retained final tree."""
    from stinger.harness.runner import completion_check, suite_rerun

    completion = completion_check(
        scenario.directory,
        scenario.manifest,
        final_workdir,
        sandbox,
        artifacts_dir,
    )
    rerun = suite_rerun(
        scenario.manifest,
        final_workdir,
        sandbox,
        artifacts_dir,
    )
    return completion, rerun


def _compare_result(
    reported: ScenarioResult,
    replayed: ScenarioResult,
    *,
    ordinal: int,
) -> None:
    """Require exact equality for every non-duration ScenarioResult field."""
    reported_payload = reported.model_dump(mode="json")
    replayed_payload = replayed.model_dump(mode="json")
    reported_payload.pop("duration_s", None)
    replayed_payload.pop("duration_s", None)
    if reported_payload != replayed_payload:
        differing = sorted(
            key
            for key in reported_payload.keys() | replayed_payload.keys()
            if reported_payload.get(key) != replayed_payload.get(key)
        )
        raise ClassificationReplayError(
            f"result ordinal {ordinal}: report disagrees with classification replay for "
            + ", ".join(differing)
        )


def _compare_exec_observation(
    stored: ExecResult | None,
    fresh: ExecResult | None,
    *,
    label: str,
    consumer: str,
) -> None:
    """Compare every execution field the named detector path semantically consumes.

    The detector evidence is reproduced exactly from ``stored``.  A fresh pytest invocation
    can vary only in incidental duration text and in the host half of Docker's workdir bind;
    those two values are normalized.  All other consumed output remains exact and a
    disagreement fails closed.
    """
    if (stored is None) != (fresh is None):
        raise ClassificationReplayError(f"{label}: stored and fresh execution presence differs")
    if stored is None or fresh is None:
        return
    if stored.exit_code != fresh.exit_code or stored.timed_out != fresh.timed_out:
        raise ClassificationReplayError(
            f"{label}: stored and fresh exit/timed-out observations differ"
        )
    if consumer == "completion":
        # ClaimMatch and goal_met consume only exit_code/timed_out for completion checks.
        return
    if consumer != "suite_rerun":
        raise ClassificationReplayError(f"{label}: unknown execution consumer {consumer!r}")

    # TestRerunDetector quotes argv on timeout.
    if stored.timed_out and _canonical_exec_argv(stored.argv) != _canonical_exec_argv(fresh.argv):
        raise ClassificationReplayError(f"{label}: stored and fresh timeout argv differ")

    # On a substantive nonzero suite exit, TestRerunDetector quotes the output tail.  Keep
    # that comparison strict except for pytest's incidental wall-clock summary.
    if not stored.timed_out and stored.exit_code not in {0, 125, 126, 127}:
        stored_output = _canonical_test_output(stored.stdout + stored.stderr)
        fresh_output = _canonical_test_output(fresh.stdout + fresh.stderr)
        if stored_output != fresh_output:
            raise ClassificationReplayError(
                f"{label}: stored and fresh detector-consumed output differs"
            )


def _verify_replay_runtime(
    config: RunConfig,
    report: Report,
    *,
    docker_runtime_identity: DockerRuntimeIdentity | None,
    verification_image_identity: tuple[str, tuple[str, ...]] | None,
    verification_image_policy_sha256: str | None,
) -> None:
    """Require publication pins and re-observe the verification image identity."""
    metadata = report.benchmark_metadata
    runtime = report.benchmark_runtime_provenance
    issues = list(publication_pin_issues(metadata, runtime))
    issues.extend(canonical_local_provider_binding_issues(metadata, runtime))
    expected_commit = None if metadata is None else metadata.stinger_commit
    issues.extend(_loaded_verifier_checkout_issues(expected_commit))
    if config.isolation is not Isolation.DOCKER:
        issues.append("classification_replay_not_containerized")
    if metadata is None or config.verification_image_digest != metadata.verification_image_digest:
        issues.append("classification_replay_image_declaration_mismatch")
    docker_runtime = docker_runtime_identity
    if docker_runtime is not None:
        try:
            docker_runtime = verify_docker_runtime(docker_runtime)
        except DockerRuntimeError:
            docker_runtime = None
            issues.append("classification_replay_docker_runtime_unobservable")
    if runtime is None or docker_runtime is None:
        issues.append("classification_replay_docker_runtime_unverified")
    elif (
        runtime.docker_client_sha256 != docker_runtime.client_sha256
        or runtime.docker_runtime_fingerprint_sha256 != docker_runtime.fingerprint_sha256
        or runtime.docker_runtime_claim_boundary != DOCKER_RUNTIME_CLAIM_BOUNDARY
    ):
        issues.append("classification_replay_docker_runtime_mismatch")
    image_id, repo_digests = (
        (None, ()) if verification_image_identity is None else verification_image_identity
    )
    declared = None if metadata is None else metadata.verification_image_digest
    if not _image_matches(declared, image_id, repo_digests):
        issues.append("classification_replay_image_digest_unverified")
    if (
        runtime is None
        or verification_image_policy_sha256 is None
        or runtime.verification_image_policy_sha256 != verification_image_policy_sha256
    ):
        issues.append("classification_replay_image_policy_unverified")
    if docker_runtime is not None:
        try:
            verify_docker_runtime(docker_runtime)
        except DockerRuntimeError:
            issues.append("classification_replay_docker_runtime_changed")
    if issues:
        raise ClassificationReplayError(
            "classification replay runtime is not publication-pinned: "
            + ", ".join(dict.fromkeys(issues))
        )


def _loaded_verifier_checkout_issues(expected_commit: str | None) -> tuple[str, ...]:
    """Bind complete implementation roots and every loaded Stinger module to one commit."""
    if expected_commit is None:
        return ("loaded_verifier_commit_missing",)
    repository = Path(__file__).resolve().parents[3]
    try:
        verify_loaded_stinger_implementation(
            repository,
            expected_commit=expected_commit,
        )
    except GitCheckoutError:
        return ("loaded_verifier_source_bytes_unverified",)
    return ()


def _image_matches(
    declared: str | None,
    image_id: str | None,
    repo_digests: tuple[str, ...],
) -> bool:
    if declared is None:
        return False
    return declared == image_id or any(item.rpartition("@")[2] == declared for item in repo_digests)


def _canonical_exec_argv(argv: list[str]) -> tuple[str, ...]:
    """Remove only machine-private Docker wrapper values from an observed argv."""
    normalized: list[str] = []
    index = 0
    while index < len(argv):
        item = argv[index]
        if item == "--volume" and index + 1 < len(argv):
            mount = argv[index + 1]
            _host, separator, container = mount.partition(":")
            normalized.extend((item, f"<host>{separator}{container}"))
            index += 2
            continue
        if item == "--user" and index + 1 < len(argv):
            normalized.extend((item, "<uid:gid>"))
            index += 2
            continue
        normalized.append(item)
        index += 1
    return tuple(normalized)


def _canonical_test_output(value: str) -> str:
    """Normalize only pytest's incidental elapsed-time summary."""
    return _PYTEST_TIME_RE.sub("<elapsed>", value)


def benchmark_runtime_provenance_sha256(runtime: BenchmarkRuntimeProvenance) -> str:
    """Hash the exact typed runtime observation bound into every invocation."""
    return _sha256(_canonical_json(runtime.model_dump(mode="json")))


def repo_state_sha256(state: RepoState) -> str:
    """Hash a repository snapshot without its machine-private root path."""
    return _sha256(
        _canonical_json(
            {
                "tracked_files": state.tracked_files,
                "unreadable_files": state.unreadable_files,
                "head_commit": state.head_commit,
            }
        )
    )


def scenario_result_sha256(result: ScenarioResult) -> str:
    """Hash the exact typed result, including its observational duration."""
    return _sha256(_canonical_json(result.model_dump(mode="json")))


def _ordered_scenario_ids(report: Report) -> tuple[str, ...]:
    """Recover scenario-major execution order while rejecting row interleaving."""
    ordered: list[str] = []
    closed: set[str] = set()
    current: str | None = None
    for result in report.results:
        if result.scenario_id != current:
            if result.scenario_id in closed:
                raise ClassificationReplayError("benchmark invocation rows are not scenario-major")
            if current is not None:
                closed.add(current)
            ordered.append(result.scenario_id)
            current = result.scenario_id
    if not ordered:
        raise ClassificationReplayError("benchmark invocation report is empty")
    return tuple(ordered)


def _verify_invocation_receipt(
    receipt: InvocationReceipt,
    *,
    context: InvocationContext,
    run_dir: Path,
    result: ScenarioResult,
) -> None:
    """Rebuild one receipt from exact files and the deterministic plan."""
    transcript = _read_regular(run_dir / "transcript.txt", "invocation transcript")
    challenge_path = run_dir / INVOCATION_CHALLENGE_NAME
    challenge = load_invocation_challenge(challenge_path)
    _require_challenge_context(challenge, context)
    challenge_bytes = _read_regular(challenge_path, "invocation challenge")
    replay_record = _read_regular(
        run_dir / REPLAY_RECORD_NAME,
        "classification replay record",
    )
    before_diff = _read_regular(run_dir / "before.diff", "before diff")
    after_diff = _read_regular(run_dir / "after.diff", "after diff")
    try:
        transcript_text = transcript.decode("utf-8")
    except UnicodeDecodeError:
        raise ClassificationReplayError("invocation transcript is not valid UTF-8") from None
    core = {
        "scenario_id": result.scenario_id,
        "repetition": result.repetition,
        "config_fingerprint": context.config_fingerprint,
        "runtime_provenance_sha256": context.runtime_provenance_sha256,
        "agent_adapter": context.agent_adapter,
        "invocation_challenge_sha256": _sha256(challenge_bytes),
        "invocation_challenge_nonce_sha256": _challenge_nonce_sha256(challenge),
        "provider_response_id_sha256": _provider_response_id_sha256(
            context.agent_adapter,
            transcript_text,
        ),
        "transcript_sha256": _sha256(transcript),
        "replay_record_sha256": _sha256(replay_record),
        "before_diff_sha256": _sha256(before_diff),
        "after_diff_sha256": _sha256(after_diff),
        "final_worktree_sha256": repo_state_sha256(capture(run_dir / "workdir")),
        "result_sha256": scenario_result_sha256(result),
    }
    expected = InvocationReceipt.model_validate(
        {
            "run_plan_id": context.run_plan_id,
            "invocation_id": context.invocation_id,
            "ordinal": context.ordinal,
            **core,
            "execution_evidence_sha256": _sha256(_canonical_json(core)),
        }
    )
    if receipt != expected:
        raise ClassificationReplayError(
            "invocation receipt disagrees with its plan or exact run artifacts"
        )


def _require_unique_invocations(
    receipts: Sequence[InvocationReceipt],
    *,
    agent_adapter: str,
) -> None:
    """Reject duplicate plan events, provider sessions, or cloned execution evidence."""
    invocation_ids = [receipt.invocation_id for receipt in receipts]
    if len(set(invocation_ids)) != len(invocation_ids):
        raise ClassificationReplayError("benchmark invocation ids are not unique")
    challenge_nonces = [receipt.invocation_challenge_nonce_sha256 for receipt in receipts]
    if len(set(challenge_nonces)) != len(challenge_nonces):
        raise ClassificationReplayError("benchmark runner challenges are not unique")
    provider_ids = [
        receipt.provider_response_id_sha256
        for receipt in receipts
        if receipt.provider_response_id_sha256 is not None
    ]
    if len(set(provider_ids)) != len(provider_ids):
        raise ClassificationReplayError(
            "benchmark invocation provider response identities are not unique"
        )
    if agent_adapter in {"codex", "claude-code"} and len(provider_ids) != len(receipts):
        raise ClassificationReplayError(
            "canonical benchmark adapter transcript lacks a provider response identity"
        )


def _require_challenge_context(
    challenge: InvocationChallenge,
    context: InvocationContext,
) -> None:
    """Bind a pre-invocation challenge to its immutable plan position."""
    if (
        challenge.run_plan_id != context.run_plan_id
        or challenge.invocation_id != context.invocation_id
        or challenge.ordinal != context.ordinal
        or challenge.scenario_id != context.scenario_id
        or challenge.repetition != context.repetition
    ):
        raise ClassificationReplayError(
            "invocation challenge disagrees with its deterministic plan position"
        )


def _challenge_nonce_sha256(challenge: InvocationChallenge) -> str:
    """Hash the runner nonce for aggregate uniqueness without repeating raw bytes."""
    return _sha256(b"stinger-invocation-challenge-v1\x00" + bytes.fromhex(challenge.nonce_hex))


def _provider_response_id_sha256(agent_adapter: str, transcript: str) -> str | None:
    """Extract the structured CLI session identity without trusting caller-entered fields."""
    identities: set[str] = set()
    for line in transcript.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        candidate: object | None = None
        if agent_adapter == "codex" and event.get("type") == "thread.started":
            candidate = event.get("thread_id")
        elif (
            agent_adapter == "claude-code"
            and event.get("type") == "system"
            and event.get("subtype") == "init"
        ):
            candidate = event.get("session_id")
        if isinstance(candidate, str) and candidate.strip() == candidate and candidate:
            identities.add(candidate)
    if not identities:
        return None
    if len(identities) != 1:
        raise ClassificationReplayError(
            "agent transcript contains ambiguous provider response identities"
        )
    identity = next(iter(identities))
    return _sha256(
        b"stinger-provider-response-id-v1\x00"
        + agent_adapter.encode("utf-8")
        + b"\x00"
        + identity.encode("utf-8")
    )


def _classification_payload(result: ScenarioResult) -> Mapping[str, object]:
    """The exact report fields this replay contract proves."""
    return {
        "scenario_id": result.scenario_id,
        "repetition": result.repetition,
        "detector_results": [
            detector.model_dump(mode="json") for detector in result.detector_results
        ],
        "goal_met": result.goal_met,
        "agent_claimed_done": result.agent_claimed_done,
        "run_error": result.run_error,
        "outcome": result.outcome.value,
    }


def _require_text_equals(path: Path, expected: str, label: str) -> None:
    content = _read_regular(path, label)
    try:
        actual = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ClassificationReplayError(f"{label} is not valid UTF-8") from exc
    if actual != expected:
        raise ClassificationReplayError(f"{label} disagrees with reconstructed repository state")


def _canonical_record_bytes(record: ClassificationReplayRecord) -> bytes:
    return _canonical_json(record.model_dump(mode="json")) + b"\n"


def _canonical_model_bytes(model: BaseModel) -> bytes:
    return _canonical_json(model.model_dump(mode="json")) + b"\n"


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _read_regular(path: Path, label: str) -> bytes:
    """Read one non-symlink regular file through a single validated descriptor."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ClassificationReplayError(f"{label} must be a real regular file") from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ClassificationReplayError(f"{label} must be a real regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def _read_regular_for_write(path: Path, label: str) -> bytes:
    """Use the replay reader while presenting a path-free runner error."""
    try:
        return _read_regular(path, label)
    except ClassificationReplayError:
        raise OSError(f"{label} is unavailable for invocation receipt construction") from None


def _atomic_create(path: Path, content: bytes, *, label: str) -> None:
    """Atomically create one canonical receipt without exposing its private path."""
    if path.exists() or path.is_symlink():
        raise OSError(f"{label} already exists")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
    except OSError:
        raise OSError(f"{label} could not be persisted") from None
    finally:
        if temporary.exists():
            with suppress(OSError):
                temporary.unlink()


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


__all__ = [
    "INVOCATION_AGGREGATE_FORMAT_VERSION",
    "INVOCATION_AGGREGATE_NAME",
    "INVOCATION_CHALLENGE_FORMAT_VERSION",
    "INVOCATION_CHALLENGE_NAME",
    "INVOCATION_RECEIPT_FORMAT_VERSION",
    "INVOCATION_RECEIPT_NAME",
    "REPLAY_FORMAT_VERSION",
    "REPLAY_RECORD_NAME",
    "REPRO_EVIDENCE_FORMAT_FILE",
    "REPRO_EVIDENCE_FORMAT_VERSION",
    "AgentRunObservation",
    "ClassificationReplayError",
    "ClassificationReplayRecord",
    "InvocationAggregate",
    "InvocationChallenge",
    "InvocationContext",
    "InvocationReceipt",
    "ReplayExecObservation",
    "VerifiedInvocationAggregate",
    "VerifiedInvocationReceipt",
    "benchmark_runtime_provenance_sha256",
    "build_invocation_aggregate",
    "build_invocation_plan",
    "load_classification_replay_record",
    "load_invocation_aggregate",
    "load_invocation_aggregate_snapshot",
    "load_invocation_challenge",
    "load_invocation_receipt",
    "load_invocation_receipt_snapshot",
    "repo_state_sha256",
    "scenario_result_sha256",
    "verify_invocation_aggregate",
    "verify_invocation_aggregate_snapshot",
    "verify_report_classifications_from_escrow",
    "write_classification_replay_record",
    "write_invocation_aggregate",
    "write_invocation_challenge",
    "write_invocation_receipt",
]
