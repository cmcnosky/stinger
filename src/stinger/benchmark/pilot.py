"""Artifact-derived pilot evidence for Benchmark Protocol 2.

The release gate consumes :class:`~stinger.benchmark.gates.PilotEvidenceRecord`, whose
small shape is intentionally convenient for evaluation.  That shape is not, by itself,
proof that the outcomes came from real runs.  This module constructs the record only from
cross-verified public/escrow bundle pairs and emits a closed statement that binds every
input without disclosing provider names, model names, or host paths.

Configuration aliases are deliberately opaque.  The statement commits each alias to both
the resolved run-configuration fingerprint and the narrower agent-configuration
fingerprint, but publishes neither fingerprint.  A later signing layer can authorize the
canonical statement without needing access to the private bundle paths.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator, model_validator

from stinger.benchmark.evidence import (
    EvidenceBundleError,
    PublicLeakagePolicy,
    VerifiedArtifactReceipt,
    verify_evidence_bundle_pair,
)
from stinger.benchmark.gates import (
    CANDIDATE_RECEIPT_FORMAT_VERSION,
    CANDIDATE_VALIDATION_CONTRACT,
    REPOSITORY_SIZE_SOURCE_VERSION,
    CandidateValidationReceipt,
    CorpusScenarioRecord,
    PilotCandidateRecord,
    PilotConfigurationOutcomeRecord,
    PilotEvidenceRecord,
    RepositorySize,
    SealedCorpusRecord,
    candidate_scenario_identity_inventory_sha256,
    candidate_validation_inventory_sha256,
    compiled_benchmark_protocol,
    pilot_selection_policy_sha256,
)
from stinger.benchmark.protocol import (
    BenchmarkSplit,
    canonical_local_provider_binding_issues,
    publication_pin_issues,
)
from stinger.harness.sandbox import Isolation
from stinger.models import Family, Outcome
from stinger.report.generate import ReportMismatchError, load_report, verify_report

__all__ = [
    "PILOT_EVIDENCE_FORMAT_VERSION",
    "PilotBundleInput",
    "PilotConfigurationReceipt",
    "PilotEvidenceError",
    "PilotEvidenceStatement",
    "PilotResultReceipt",
    "VerifiedPilotReceipt",
    "build_pilot_evidence_statement",
    "canonical_pilot_evidence_statement_sha256",
    "write_pilot_evidence_statement",
]

PILOT_EVIDENCE_FORMAT_VERSION: Literal["2"] = "2"
"""Canonical statement format for Protocol 2 artifact-derived pilot evidence."""

_OPAQUE_ALIAS_PATTERN = re.compile(r"^anonymous-[0-9a-f]{16,64}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SEMVER_PATTERN = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_READ_CHUNK = 1024 * 1024
_RESOLVED_CONFIGURATION_COMMITMENT_DOMAIN = "stinger-pilot-resolved-configuration-v2"
_AGENT_CONFIGURATION_COMMITMENT_DOMAIN = "stinger-pilot-agent-configuration-v2"


class PilotEvidenceError(Exception):
    """Raised when run artifacts cannot support a truthful pilot statement."""


class _ClosedModel(BaseModel):
    """Common immutable, closed schema for pilot outputs."""

    model_config = ConfigDict(extra="forbid", frozen=True)


@dataclass(frozen=True, slots=True)
class PilotBundleInput:
    """Private locations and trust inputs for one opaque pilot configuration.

    None of these paths, signer labels, or leakage-policy values enter the statement.
    """

    configuration_alias: str
    public_bundle: Path
    escrow_bundle: Path
    leakage_policy: PublicLeakagePolicy
    protocol_allowed_signers: Path
    protocol_signer_identity: str


class PilotConfigurationReceipt(_ClosedModel):
    """Path-free commitments for one fully verified pilot run."""

    configuration_alias: str
    resolved_configuration_commitment_sha256: str
    agent_configuration_commitment_sha256: str
    report_sha256: str
    runtime_receipt_sha256: str
    public_evidence_manifest_sha256: str
    escrow_evidence_manifest_sha256: str
    result_inventory_sha256: str

    @field_validator("configuration_alias")
    @classmethod
    def _opaque_alias(cls, value: str) -> str:
        """Require a random-looking alias that cannot itself name a vendor or model."""
        if _OPAQUE_ALIAS_PATTERN.fullmatch(value) is None:
            raise ValueError(
                "configuration_alias must use anonymous- followed by 16-64 lowercase hex digits"
            )
        return value

    @field_validator(
        "resolved_configuration_commitment_sha256",
        "agent_configuration_commitment_sha256",
        "report_sha256",
        "runtime_receipt_sha256",
        "public_evidence_manifest_sha256",
        "escrow_evidence_manifest_sha256",
        "result_inventory_sha256",
    )
    @classmethod
    def _canonical_hash(cls, value: str) -> str:
        """Require exact lowercase SHA-256 bindings."""
        if _SHA256_PATTERN.fullmatch(value) is None:
            raise ValueError("pilot configuration artifact must be a canonical sha256")
        return value


class PilotResultReceipt(_ClosedModel):
    """One exact result bound to its anonymous configuration and report."""

    scenario_id: str
    cluster_id: str
    configuration_alias: str
    repetition: Literal[0]
    outcome: Outcome
    result_sha256: str

    @field_validator("scenario_id", "cluster_id")
    @classmethod
    def _canonical_identifier(cls, value: str) -> str:
        """Reject blank or whitespace-ambiguous scenario identities."""
        if not value or value != value.strip() or any(character.isspace() for character in value):
            raise ValueError("pilot result identifiers must be nonblank and whitespace-free")
        return value

    @field_validator("configuration_alias")
    @classmethod
    def _opaque_alias(cls, value: str) -> str:
        """Use the same opaque alias contract as configuration receipts."""
        if _OPAQUE_ALIAS_PATTERN.fullmatch(value) is None:
            raise ValueError("pilot result configuration alias is not opaque")
        return value

    @field_validator("result_sha256")
    @classmethod
    def _canonical_hash(cls, value: str) -> str:
        """Require an exact typed-result hash."""
        if _SHA256_PATTERN.fullmatch(value) is None:
            raise ValueError("pilot result hash must be a canonical sha256")
        return value

    @field_validator("outcome")
    @classmethod
    def _scorable_outcome(cls, value: Outcome) -> Outcome:
        """Never admit an unavailable run into pilot variation evidence."""
        if value is Outcome.ERROR:
            raise ValueError("ERROR outcomes cannot support pilot evidence")
        return value


class PilotEvidenceStatement(_ClosedModel):
    """Canonical, disclosure-safe statement over exact pilot run artifacts."""

    format_version: Literal["2"]
    benchmark_protocol_version: str
    rubric_version: str
    corpus_version: str
    corpus_hash: str
    candidate_corpus_hash: str
    evaluated_corpus_hash: str
    evaluated_split: BenchmarkSplit
    protocol_sha256: str
    candidate_validation_receipt_sha256: str
    candidate_scenario_identity_inventory_sha256: str
    selection_protocol_sha256: str
    scenario_count: int
    configuration_count: int
    pilot_evidence_sha256: str
    pilot: PilotEvidenceRecord
    configurations: tuple[PilotConfigurationReceipt, ...]
    results: tuple[PilotResultReceipt, ...]

    @field_validator("benchmark_protocol_version", "rubric_version", "corpus_version")
    @classmethod
    def _semantic_version(cls, value: str) -> str:
        """Require complete semantic versions rather than informal labels."""
        if _SEMVER_PATTERN.fullmatch(value) is None:
            raise ValueError("pilot statement versions must be semantic versions")
        return value

    @field_validator(
        "corpus_hash",
        "candidate_corpus_hash",
        "evaluated_corpus_hash",
        "protocol_sha256",
        "candidate_validation_receipt_sha256",
        "candidate_scenario_identity_inventory_sha256",
        "selection_protocol_sha256",
        "pilot_evidence_sha256",
    )
    @classmethod
    def _canonical_hash(cls, value: str) -> str:
        """Require exact lowercase SHA-256 content commitments."""
        if _SHA256_PATTERN.fullmatch(value) is None:
            raise ValueError("pilot statement artifact must be a canonical sha256")
        return value

    @field_validator("evaluated_split")
    @classmethod
    def _candidate_or_sealed(cls, value: BenchmarkSplit) -> BenchmarkSplit:
        """Pilot evidence may describe the candidate snapshot or its sealed freeze."""
        if value not in {BenchmarkSplit.CANDIDATE, BenchmarkSplit.SEALED}:
            raise ValueError("pilot evidence must use the candidate or sealed split")
        return value

    @model_validator(mode="after")
    def _cross_bind_statement(self) -> PilotEvidenceStatement:
        """Reject internally inconsistent grids, hashes, ordering, or counts."""
        aliases = tuple(item.configuration_alias for item in self.configurations)
        if (
            not aliases
            or aliases != tuple(sorted(aliases))
            or len(aliases) != len(set(aliases))
            or self.configuration_count != len(aliases)
        ):
            raise ValueError("pilot configurations must be nonempty, unique, and sorted")

        candidates = self.pilot.candidate_pool
        scenario_ids = tuple(item.scenario_id for item in candidates)
        if (
            not scenario_ids
            or scenario_ids != tuple(sorted(scenario_ids))
            or len(scenario_ids) != len(set(scenario_ids))
            or self.scenario_count != len(scenario_ids)
        ):
            raise ValueError("pilot scenarios must be nonempty, unique, and sorted")
        if self.pilot.selection_protocol_sha256 != self.selection_protocol_sha256:
            raise ValueError("pilot selection protocol hash is not cross-bound")
        expected_selection_policy_sha256 = pilot_selection_policy_sha256(
            compiled_benchmark_protocol().pilot_selection_policy
        )
        if self.selection_protocol_sha256 != expected_selection_policy_sha256:
            raise ValueError(
                "pilot selection hash does not bind the protocol-frozen complete-corpus policy"
            )
        expected_evaluated_hash = (
            self.candidate_corpus_hash
            if self.evaluated_split is BenchmarkSplit.CANDIDATE
            else self.corpus_hash
        )
        if self.evaluated_corpus_hash != expected_evaluated_hash:
            raise ValueError("pilot evaluated corpus hash disagrees with its lifecycle split")
        if self.pilot_evidence_sha256 != _canonical_model_sha256(self.pilot):
            raise ValueError("pilot evidence hash does not match the embedded record")

        expected_outcomes: dict[tuple[str, str], Outcome] = {}
        expected_clusters: dict[str, str] = {}
        for candidate in candidates:
            outcome_aliases = tuple(item.configuration_alias for item in candidate.outcomes)
            if outcome_aliases != aliases:
                raise ValueError("every pilot scenario must cover the exact configuration set")
            expected_clusters[candidate.scenario_id] = candidate.cluster_id
            for outcome in candidate.outcomes:
                expected_outcomes[(candidate.scenario_id, outcome.configuration_alias)] = (
                    outcome.outcome
                )

        result_keys = tuple(
            (item.scenario_id, item.configuration_alias, item.repetition) for item in self.results
        )
        if result_keys != tuple(sorted(result_keys)) or len(result_keys) != len(set(result_keys)):
            raise ValueError("pilot result receipts must be unique and sorted")
        expected_keys = {
            (scenario_id, alias, 0) for scenario_id in scenario_ids for alias in aliases
        }
        if set(result_keys) != expected_keys:
            raise ValueError("pilot result receipts do not form the complete scenario grid")
        for result in self.results:
            if expected_clusters[result.scenario_id] != result.cluster_id:
                raise ValueError("pilot result cluster binding disagrees with the evidence record")
            if (
                expected_outcomes[(result.scenario_id, result.configuration_alias)]
                is not result.outcome
            ):
                raise ValueError("pilot result outcome disagrees with the evidence record")

        receipts_by_alias = {item.configuration_alias: item for item in self.configurations}
        for alias in aliases:
            alias_results = tuple(
                result for result in self.results if result.configuration_alias == alias
            )
            if receipts_by_alias[alias].result_inventory_sha256 != _result_inventory_sha256(
                alias_results
            ):
                raise ValueError("pilot result inventory is not cross-bound")
        return self


class VerifiedPilotReceipt(_ClosedModel):
    """Typed handoff proving a statement survived the artifact-derived builder."""

    statement: PilotEvidenceStatement
    canonical_statement_sha256: str

    @field_validator("canonical_statement_sha256")
    @classmethod
    def _canonical_hash(cls, value: str) -> str:
        """Require the canonical statement digest representation."""
        if _SHA256_PATTERN.fullmatch(value) is None:
            raise ValueError("pilot statement hash must be a canonical sha256")
        return value

    @model_validator(mode="after")
    def _statement_hash_matches(self) -> VerifiedPilotReceipt:
        """Bind the receipt to the exact canonical statement bytes."""
        if self.canonical_statement_sha256 != canonical_pilot_evidence_statement_sha256(
            self.statement
        ):
            raise ValueError("verified pilot receipt does not bind its statement")
        return self


def build_pilot_evidence_statement(
    *,
    corpus: SealedCorpusRecord,
    candidate_receipt: Path,
    runs: tuple[PilotBundleInput, ...],
) -> VerifiedPilotReceipt:
    """Build pilot evidence from exact verified run bundles.

    Each run must cover the complete supplied scenario set exactly once.  The builder
    refuses unpinned runtime provenance, duplicate configurations, ERROR outcomes, and any
    missing, extra, or mutated scenario identity.  Provider/model identities are used only
    to validate publication pins and derive one-way commitments; they are never emitted.

    Args:
        corpus: Candidate-to-sealed scenario identity and construction record.
        candidate_receipt: Canonical candidate validation receipt bytes already named by
            ``corpus``.  Signature authorization is intentionally added by the caller's
            later trust layer.
        runs: Public/escrow pairs under opaque configuration aliases.

    Returns:
        A verified typed receipt containing the disclosure-safe canonical statement.

    Raises:
        PilotEvidenceError: If any candidate, protocol, bundle, report, runtime, result, or
            output binding cannot be proved.
    """
    protocol = compiled_benchmark_protocol()
    _validate_corpus_identity(corpus)
    candidate_bytes = _read_regular_file(candidate_receipt, "candidate receipt")
    candidate = _load_candidate_receipt(candidate_bytes)
    candidate_receipt_sha256 = _sha256(candidate_bytes)
    _cross_bind_candidate_receipt(
        candidate,
        candidate_receipt_sha256=candidate_receipt_sha256,
        corpus=corpus,
    )
    selection_protocol_sha256 = pilot_selection_policy_sha256(protocol.pilot_selection_policy)

    aliases = tuple(run.configuration_alias for run in runs)
    if (
        not aliases
        or len(aliases) != len(set(aliases))
        or any(_OPAQUE_ALIAS_PATTERN.fullmatch(alias) is None for alias in aliases)
    ):
        raise PilotEvidenceError("pilot run aliases must be unique opaque identifiers")

    expected_by_id = {scenario.scenario_id: scenario for scenario in corpus.scenarios}
    configuration_receipts: list[PilotConfigurationReceipt] = []
    result_receipts: list[PilotResultReceipt] = []
    outcomes_by_scenario: dict[str, dict[str, Outcome]] = {
        scenario_id: {} for scenario_id in expected_by_id
    }
    observed_splits: set[BenchmarkSplit] = set()
    observed_resolved_fingerprints: set[str] = set()
    observed_agent_fingerprints: set[str] = set()
    protocol_bytes_sha256: str | None = None

    for run in sorted(runs, key=lambda item: item.configuration_alias):
        try:
            receipt = verify_evidence_bundle_pair(
                run.public_bundle,
                run.escrow_bundle,
                run.leakage_policy,
                trusted_allowed_signers=run.protocol_allowed_signers,
                expected_signer_identity=run.protocol_signer_identity,
            )
        except (EvidenceBundleError, OSError, ValueError):
            raise PilotEvidenceError("pilot evidence bundle verification failed") from None
        _verify_receipt_snapshot(receipt)
        if receipt.protocol != protocol:
            raise PilotEvidenceError("pilot protocol does not match the compiled contract")
        current_protocol_sha256 = _sha256(receipt.public_bundle.protocol_bytes)
        if protocol_bytes_sha256 is None:
            protocol_bytes_sha256 = current_protocol_sha256
        elif current_protocol_sha256 != protocol_bytes_sha256:
            raise PilotEvidenceError("pilot runs do not share exact protocol bytes")

        (
            configuration_receipt,
            current_results,
            split,
            resolved_fingerprint,
            agent_fingerprint,
        ) = _derive_run_receipts(
            run.configuration_alias,
            receipt,
            corpus=corpus,
            expected_by_id=expected_by_id,
            candidate_corpus_hash=candidate.candidate_corpus_hash,
        )
        if resolved_fingerprint in observed_resolved_fingerprints:
            raise PilotEvidenceError("pilot aliases do not name distinct configurations")
        if agent_fingerprint in observed_agent_fingerprints:
            raise PilotEvidenceError("pilot aliases do not name distinct agent configurations")
        observed_resolved_fingerprints.add(resolved_fingerprint)
        observed_agent_fingerprints.add(agent_fingerprint)
        observed_splits.add(split)
        configuration_receipts.append(configuration_receipt)
        result_receipts.extend(current_results)
        for result in current_results:
            outcomes_by_scenario[result.scenario_id][run.configuration_alias] = result.outcome

    if protocol_bytes_sha256 is None or len(observed_splits) != 1:
        raise PilotEvidenceError("pilot runs do not share one candidate or sealed split")
    evaluated_split = next(iter(observed_splits))
    sorted_aliases = tuple(sorted(aliases))
    candidate_pool = tuple(
        PilotCandidateRecord(
            scenario_id=scenario.scenario_id,
            cluster_id=scenario.cluster_id,
            outcomes=tuple(
                PilotConfigurationOutcomeRecord(
                    configuration_alias=alias,
                    outcome=outcomes_by_scenario[scenario.scenario_id][alias],
                )
                for alias in sorted_aliases
            ),
        )
        for scenario in sorted(corpus.scenarios, key=lambda item: item.scenario_id)
    )
    pilot = PilotEvidenceRecord(
        candidate_pool=candidate_pool,
        selection_protocol_sha256=selection_protocol_sha256,
    )
    statement = PilotEvidenceStatement(
        format_version=PILOT_EVIDENCE_FORMAT_VERSION,
        benchmark_protocol_version=protocol.benchmark_protocol_version,
        rubric_version=protocol.rubric_version,
        corpus_version=corpus.corpus_version,
        corpus_hash=corpus.corpus_hash,
        candidate_corpus_hash=candidate.candidate_corpus_hash,
        evaluated_corpus_hash=(
            candidate.candidate_corpus_hash
            if evaluated_split is BenchmarkSplit.CANDIDATE
            else corpus.corpus_hash
        ),
        evaluated_split=evaluated_split,
        protocol_sha256=protocol_bytes_sha256,
        candidate_validation_receipt_sha256=candidate_receipt_sha256,
        candidate_scenario_identity_inventory_sha256=(
            candidate_scenario_identity_inventory_sha256(corpus.scenarios)
        ),
        selection_protocol_sha256=selection_protocol_sha256,
        scenario_count=len(corpus.scenarios),
        configuration_count=len(runs),
        pilot_evidence_sha256=_canonical_model_sha256(pilot),
        pilot=pilot,
        configurations=tuple(
            sorted(
                configuration_receipts,
                key=lambda item: item.configuration_alias,
            )
        ),
        results=tuple(
            sorted(
                result_receipts,
                key=lambda item: (
                    item.scenario_id,
                    item.configuration_alias,
                    item.repetition,
                ),
            )
        ),
    )
    return VerifiedPilotReceipt(
        statement=statement,
        canonical_statement_sha256=canonical_pilot_evidence_statement_sha256(statement),
    )


def canonical_pilot_evidence_statement_sha256(
    statement: PilotEvidenceStatement,
) -> str:
    """Hash the exact canonical bytes written for one pilot statement."""
    return _sha256(_canonical_model_bytes(statement))


def write_pilot_evidence_statement(
    destination: Path,
    statement: PilotEvidenceStatement,
) -> None:
    """Atomically create canonical statement JSON without overwriting."""
    _atomic_create(destination, _canonical_model_bytes(statement))


def _derive_run_receipts(
    alias: str,
    receipt: VerifiedArtifactReceipt,
    *,
    corpus: SealedCorpusRecord,
    expected_by_id: dict[str, CorpusScenarioRecord],
    candidate_corpus_hash: str,
) -> tuple[
    PilotConfigurationReceipt,
    tuple[PilotResultReceipt, ...],
    BenchmarkSplit,
    str,
    str,
]:
    """Verify one run and derive its disclosure-safe configuration/result receipts."""
    report = receipt.report
    try:
        verify_report(report)
    except (ReportMismatchError, ValueError):
        raise PilotEvidenceError("pilot report failed deterministic verification") from None
    if (
        report.rubric_version != receipt.protocol.rubric_version
        or report.benchmark_protocol_version != receipt.protocol.benchmark_protocol_version
        or report.config_fingerprint != receipt.config.fingerprint()
        or report.partial
    ):
        raise PilotEvidenceError("pilot report does not bind the required protocol and corpus")
    metadata = report.benchmark_metadata
    runtime = report.benchmark_runtime_provenance
    if (
        metadata is None
        or runtime is None
        or publication_pin_issues(metadata, runtime)
        or canonical_local_provider_binding_issues(metadata, runtime)
    ):
        raise PilotEvidenceError("pilot report lacks verified runtime provenance")
    agent_fingerprint = metadata.agent_configuration_fingerprint
    if agent_fingerprint is None:
        raise PilotEvidenceError("pilot report lacks a derived agent configuration identity")
    if (
        receipt.config.reps != 1
        or receipt.config.only is not None
        or receipt.config.isolation is not Isolation.DOCKER
        or receipt.config.agent.container_image_digest is None
        or receipt.config.verification_image_digest is None
    ):
        raise PilotEvidenceError("pilot configuration is not one complete contained execution")

    result_ids = [result.scenario_id for result in report.results]
    if (
        len(result_ids) != len(expected_by_id)
        or len(result_ids) != len(set(result_ids))
        or set(result_ids) != set(expected_by_id)
        or any(result.repetition != 0 for result in report.results)
        or any(result.outcome is Outcome.ERROR for result in report.results)
    ):
        raise PilotEvidenceError(
            "pilot report has missing, extra, duplicate, or unavailable results"
        )

    splits: set[BenchmarkSplit] = set()
    result_receipts: list[PilotResultReceipt] = []
    for result in report.results:
        expected = expected_by_id[result.scenario_id]
        if (
            result.family is not expected.family
            or result.scenario_version != expected.scenario_version
            or result.cluster_id != expected.cluster_id
            or result.benchmark_split not in {BenchmarkSplit.CANDIDATE, BenchmarkSplit.SEALED}
        ):
            raise PilotEvidenceError("pilot result identity disagrees with the candidate set")
        assert result.benchmark_split is not None
        splits.add(result.benchmark_split)
        result_receipts.append(
            PilotResultReceipt(
                scenario_id=result.scenario_id,
                cluster_id=expected.cluster_id,
                configuration_alias=alias,
                repetition=0,
                outcome=result.outcome,
                result_sha256=_canonical_model_sha256(result),
            )
        )
    if len(splits) != 1:
        raise PilotEvidenceError("pilot report mixes candidate and sealed results")
    split = next(iter(splits))
    expected_corpus_hash = (
        candidate_corpus_hash if split is BenchmarkSplit.CANDIDATE else corpus.corpus_hash
    )
    if report.corpus_hash != expected_corpus_hash:
        raise PilotEvidenceError("pilot report does not bind the evaluated corpus snapshot")

    sorted_results = tuple(
        sorted(
            result_receipts,
            key=lambda item: (item.scenario_id, item.configuration_alias, item.repetition),
        )
    )
    resolved_fingerprint = report.config_fingerprint
    configuration = PilotConfigurationReceipt(
        configuration_alias=alias,
        resolved_configuration_commitment_sha256=_configuration_commitment(
            _RESOLVED_CONFIGURATION_COMMITMENT_DOMAIN,
            alias,
            resolved_fingerprint,
        ),
        agent_configuration_commitment_sha256=_configuration_commitment(
            _AGENT_CONFIGURATION_COMMITMENT_DOMAIN,
            alias,
            agent_fingerprint,
        ),
        report_sha256=_sha256(receipt.public_bundle.report_bytes),
        runtime_receipt_sha256=_canonical_model_sha256(runtime),
        public_evidence_manifest_sha256=receipt.public_bundle.manifest_sha256,
        escrow_evidence_manifest_sha256=receipt.escrow_bundle.manifest_sha256,
        result_inventory_sha256=_result_inventory_sha256(sorted_results),
    )
    return (
        configuration,
        sorted_results,
        split,
        resolved_fingerprint,
        agent_fingerprint,
    )


def _verify_receipt_snapshot(receipt: VerifiedArtifactReceipt) -> None:
    """Recheck exact retained bytes before deriving any output commitment."""
    public = receipt.public_bundle
    escrow = receipt.escrow_bundle
    try:
        parsed = load_report(public.report_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValidationError, ReportMismatchError):
        raise PilotEvidenceError("verified pilot report bytes are malformed") from None
    if (
        parsed != receipt.report
        or public.report != receipt.report
        or escrow.report != receipt.report
        or public.report_bytes != escrow.report_bytes
        or _sha256(public.report_bytes) != public.manifest.report_sha256
        or _sha256(escrow.report_bytes) != escrow.manifest.report_sha256
        or _sha256(public.manifest_bytes) != public.manifest_sha256
        or _sha256(escrow.manifest_bytes) != escrow.manifest_sha256
        or public.manifest_bytes != _canonical_model_bytes(public.manifest)
        or escrow.manifest_bytes != _canonical_model_bytes(escrow.manifest)
        or public.protocol_bytes != escrow.protocol_bytes
        or _sha256(public.protocol_bytes) != public.manifest.protocol_sha256
        or _sha256(escrow.protocol_bytes) != escrow.manifest.protocol_sha256
        or public.protocol != receipt.protocol
        or escrow.protocol != receipt.protocol
        or public.config.fingerprint() != receipt.config.fingerprint()
        or escrow.config.fingerprint() != receipt.config.fingerprint()
    ):
        raise PilotEvidenceError("verified pilot artifact snapshot is internally inconsistent")


def _validate_corpus_identity(corpus: SealedCorpusRecord) -> None:
    """Require one unique, all-family candidate-to-sealed identity set."""
    protocol = compiled_benchmark_protocol()
    scenario_ids = [scenario.scenario_id for scenario in corpus.scenarios]
    clusters = [scenario.cluster_id for scenario in corpus.scenarios]
    family_counts = Counter(scenario.family for scenario in corpus.scenarios)
    if (
        not scenario_ids
        or len(scenario_ids) != protocol.total_scenarios
        or len(scenario_ids) != len(set(scenario_ids))
        or len(clusters) != len(set(clusters))
        or {scenario.family for scenario in corpus.scenarios} != set(Family)
        or any(family_counts[family] != protocol.scenarios_per_family for family in Family)
        or any(
            scenario.benchmark_split is not BenchmarkSplit.SEALED for scenario in corpus.scenarios
        )
    ):
        raise PilotEvidenceError("pilot corpus identity set is incomplete or ambiguous")


def _cross_bind_candidate_receipt(
    receipt: CandidateValidationReceipt,
    *,
    candidate_receipt_sha256: str,
    corpus: SealedCorpusRecord,
) -> None:
    """Bind canonical candidate validation bytes to the sealed identity inventory."""
    protocol = compiled_benchmark_protocol()
    family_counts = Counter(scenario.family for scenario in corpus.scenarios)
    size_counts = Counter(
        (scenario.family, scenario.repository_size) for scenario in corpus.scenarios
    )
    expected_by_family = {family: family_counts[family] for family in Family}
    expected_by_size = {
        family: {size: size_counts[(family, size)] for size in RepositorySize} for family in Family
    }
    if (
        corpus.candidate_validation_receipt_sha256 is None
        or corpus.candidate_validation_receipt_sha256 != candidate_receipt_sha256
        or receipt.format_version != CANDIDATE_RECEIPT_FORMAT_VERSION
        or receipt.benchmark_protocol_version != protocol.benchmark_protocol_version
        or receipt.rubric_version != protocol.rubric_version
        or receipt.corpus_version != corpus.corpus_version
        or receipt.validation_contract != CANDIDATE_VALIDATION_CONTRACT
        or receipt.repository_size_source != REPOSITORY_SIZE_SOURCE_VERSION
        or receipt.scenario_count != len(corpus.scenarios)
        or receipt.scenarios_by_family != expected_by_family
        or receipt.scenarios_by_family_and_size != expected_by_size
        or receipt.unique_cluster_count != len(corpus.scenarios)
        or receipt.machine_validation_count != len(corpus.scenarios)
        or receipt.canary_count != len(corpus.scenarios)
        or receipt.scenario_identity_inventory_sha256
        != candidate_scenario_identity_inventory_sha256(corpus.scenarios)
        or receipt.validation_inventory_sha256
        != candidate_validation_inventory_sha256(corpus.scenarios)
        or corpus.canary_validation_receipt_sha256 is None
        or receipt.canary_inventory_sha256 != corpus.canary_validation_receipt_sha256
    ):
        raise PilotEvidenceError("candidate validation receipt is not bound to the scenario set")


def _load_candidate_receipt(content: bytes) -> CandidateValidationReceipt:
    """Load duplicate-free canonical candidate receipt JSON."""
    try:
        raw = json.loads(content.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
        receipt = CandidateValidationReceipt.model_validate(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError):
        raise PilotEvidenceError("candidate validation receipt is malformed") from None
    if content != _canonical_model_bytes(receipt):
        raise PilotEvidenceError("candidate validation receipt is not canonical")
    return receipt


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON object keys at every nesting level."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _configuration_commitment(domain: str, alias: str, fingerprint: str) -> str:
    """Commit an opaque alias to one nonpublished configuration fingerprint."""
    return _canonical_payload_sha256(
        {
            "domain": domain,
            "configuration_alias": alias,
            "configuration_fingerprint": fingerprint,
        }
    )


def _result_inventory_sha256(results: tuple[PilotResultReceipt, ...]) -> str:
    """Hash one canonical per-configuration result-receipt inventory."""
    return _canonical_payload_sha256(
        {"results": [item.model_dump(mode="json") for item in results]}
    )


def _canonical_model_sha256(model: BaseModel) -> str:
    """Hash one typed model in canonical JSON form without output-file whitespace."""
    return _canonical_payload_sha256(model.model_dump(mode="json"))


def _canonical_payload_sha256(payload: object) -> str:
    """Hash one JSON-compatible payload with stable ordering."""
    return _sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _canonical_model_bytes(model: BaseModel) -> bytes:
    """Serialize one closed model deterministically for signing or storage."""
    return (
        json.dumps(
            model.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _read_regular_file(path: Path, label: str) -> bytes:
    """Read exact nonempty regular nonsymlink bytes without exposing the path."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise PilotEvidenceError(f"{label} is unavailable") from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PilotEvidenceError(f"{label} is not a regular file")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, _READ_CHUNK)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    finally:
        os.close(descriptor)
    if size == 0:
        raise PilotEvidenceError(f"{label} is empty")
    return b"".join(chunks)


def _sha256(content: bytes) -> str:
    """Return one lowercase SHA-256 digest."""
    return hashlib.sha256(content).hexdigest()


def _atomic_create(destination: Path, content: bytes) -> None:
    """Create one canonical file atomically and refuse existing destinations."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor: int | None = None
    temporary: Path | None = None
    try:
        descriptor, raw_temporary = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        temporary = Path(raw_temporary)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        try:
            os.link(temporary, destination)
        except FileExistsError:
            raise PilotEvidenceError("pilot statement output already exists") from None
        os.unlink(temporary)
        temporary = None
    except PilotEvidenceError:
        raise
    except OSError:
        raise PilotEvidenceError("pilot statement output could not be created") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)
