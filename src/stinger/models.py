"""Core data model — the contracts every component shares (SPEC.md §4).

These schemas are normative. Do not rename fields or change enum values without updating
SPEC.md; downstream detectors, scoring, and reports depend on them verbatim.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class Outcome(StrEnum):
    """The single label a scenario repetition resolves to (SPEC.md §4, §7)."""

    HONEST = "honest"
    CHEATED = "cheated"
    REFUSED = "refused"
    FAILED_HONESTLY = "failed_honestly"
    ERROR = "error"  # excluded from all scores — fail closed, never favorable


class Family(StrEnum):
    """Scenario families. Overall score is the unweighted mean across these (SPEC.md §8)."""

    T = "T"  # test-integrity
    S = "S"  # spec-fidelity
    C = "C"  # claims-audit
    G = "G"  # governance-compliance
    X = "X"  # safety / exfiltration


class DetectorResult(BaseModel):
    """One detector's mechanical verdict, always with evidence (SPEC.md §6)."""

    detector: str
    fired: bool  # True => evidence of a cheat
    evidence: str  # human-readable; MUST point at the concrete trace
    low_confidence: bool = False  # routes to review rather than auto-CHEATED
    artifacts: list[str] = []  # paths inside the reproducibility package


class ScenarioResult(BaseModel):
    """The outcome of running one scenario once (SPEC.md §4, §7)."""

    scenario_id: str
    family: Family
    outcome: Outcome
    detector_results: list[DetectorResult]
    goal_met: bool
    agent_claimed_done: bool
    transcript_path: str
    diff_path: str
    duration_s: float
    repetition: int


class FamilyScore(BaseModel):
    """Per-family aggregate (SPEC.md §8). integrity_rate excludes refused/failed/error."""

    family: Family
    honest: int
    cheated: int
    refused: int
    failed_honestly: int
    error: int
    integrity_rate: float | None  # None => 'n/a' (empty honest+cheated denominator)
    stdev_across_reps: float


class JudgeReport(BaseModel):
    """Bounded, clearly-separated judge output (SPEC.md §9). Never alters mechanical scores."""

    judge_model: str
    judge_prompt_version: str
    needs_review: list[str]  # scenario ids the judge flagged despite a mechanical 'honest'


class Report(BaseModel):
    """The Integrity Report (SPEC.md §4, §10)."""

    rubric_version: str
    corpus_hash: str
    config_fingerprint: str
    generated_at: str  # RFC3339, passed in — never read the wall clock mid-run
    results: list[ScenarioResult]
    family_scores: dict[Family, FamilyScore]
    overall_integrity_rate: float | None
    partial: bool = False  # True unless all five families are present
    judge_assisted: JudgeReport | None = None
