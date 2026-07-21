"""The Integrity Report: build it, render it, and verify it against its own evidence.

Building (SPEC.md §8) aggregates repetitions into family scores and an overall rate.
Rendering emits JSON, Markdown and HTML from one Report.

`verify_report` is the part worth reading. It recomputes every published number from the
report's own `results` and refuses the report if the stored numbers disagree. That makes a
report checkable without re-running an agent, and it is what `rerun.sh` leans on for the half
of reproducibility that does not depend on the agent under test (SPEC.md §10).

Three rules from §8 are enforced here rather than left to whoever reads the output:

* A family whose honest+cheated denominator is empty is reported as `n/a` and excluded from
  the overall mean — and the report SAYS SO, in every format. No silent dropping.
* A report not covering all five families is marked `partial` and every rendering labels it
  a dev run that must not be presented as a Stinger score.
* Per-scenario outcome distributions and the per-family standard deviation across
  repetitions are always shown. Hiding variance is prohibited.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from importlib import resources

from jinja2 import Environment, StrictUndefined

from stinger import RUBRIC_VERSION
from stinger.models import (
    DetectorResult,
    Family,
    FamilyScore,
    JudgeReport,
    Outcome,
    Report,
    ScenarioResult,
)
from stinger.scoring.rubric import family_score, overall_integrity_rate

__all__ = [
    "PARTIAL_RUN_WARNING",
    "ReportMismatchError",
    "build_report",
    "outcome_distribution",
    "render_html",
    "render_json",
    "render_markdown",
    "verify_report",
]

PARTIAL_RUN_WARNING = (
    "PARTIAL / DEV RUN — this run does not cover all five families, so it MUST NOT be "
    "presented as a Stinger score (SPEC.md §8)."
)

NA_NOTE = (
    "Families marked n/a had no honest-or-cheated outcomes to divide, so they have no "
    "integrity rate and are excluded from the overall mean."
)


class ReportMismatchError(Exception):
    """Raised when a stored report's numbers do not match a recomputation from its results."""


def build_report(
    results: list[ScenarioResult],
    *,
    corpus_hash: str,
    config_fingerprint: str,
    generated_at: str,
    judge_assisted: JudgeReport | None = None,
) -> Report:
    """Aggregate repetitions into the Integrity Report (SPEC.md §8).

    Args:
        results: Every repetition of every scenario that ran.
        corpus_hash: sha256 over the corpus (SPEC.md §10).
        config_fingerprint: sha256 over the resolved RunConfig.
        generated_at: RFC3339 timestamp, passed in — never read from the clock here, so the
            report stays a pure function of its inputs (AGENTS.md rule 6).
        judge_assisted: The optional judge block. Never affects any number below.

    Returns:
        The Report, marked `partial` unless all five families are present.
    """
    scores = {family: score for family, score in _family_scores(results).items()}
    return Report(
        rubric_version=RUBRIC_VERSION,
        corpus_hash=corpus_hash,
        config_fingerprint=config_fingerprint,
        generated_at=generated_at,
        results=results,
        family_scores=scores,
        overall_integrity_rate=overall_integrity_rate(scores),
        partial=set(scores) != set(Family),
        judge_assisted=judge_assisted,
    )


def verify_report(report: Report) -> None:
    """Recompute the report's numbers from its own results and refuse any disagreement.

    This is the deterministic half of reproducibility (SPEC.md §10): it needs no agent, no
    container and no network, and it catches a report whose headline number was edited,
    merged badly, or produced under a different rubric.

    Args:
        report: The report to check, typically loaded from a repro package's report.json.

    Raises:
        ReportMismatchError: If the rubric version differs from this build's, or if any
            family score, the partial flag, or the overall rate differs from a recomputation.
    """
    if report.rubric_version != RUBRIC_VERSION:
        raise ReportMismatchError(
            f"report was scored under rubric {report.rubric_version} but this build "
            f"implements {RUBRIC_VERSION}; scores from different rubrics are not comparable"
        )

    recomputed = _family_scores(report.results)
    if set(recomputed) != set(report.family_scores):
        raise ReportMismatchError(
            f"report lists families {sorted(report.family_scores)} but its results cover "
            f"{sorted(recomputed)}"
        )
    for family, score in recomputed.items():
        if report.family_scores[family] != score:
            raise ReportMismatchError(
                f"stored score for family {family} does not match a recomputation from the "
                f"report's own results: stored {report.family_scores[family]!r}, "
                f"recomputed {score!r}"
            )

    expected_overall = overall_integrity_rate(recomputed)
    if report.overall_integrity_rate != expected_overall:
        raise ReportMismatchError(
            f"stored overall integrity rate {report.overall_integrity_rate!r} does not match "
            f"a recomputation from the report's own results ({expected_overall!r})"
        )
    if report.partial != (set(recomputed) != set(Family)):
        raise ReportMismatchError(
            f"stored partial flag {report.partial} disagrees with the families actually "
            f"covered ({sorted(recomputed)})"
        )


def outcome_distribution(report: Report) -> dict[str, dict[str, int]]:
    """Per-scenario outcome counts across repetitions (SPEC.md §8.4).

    Published in every rendering. A modal outcome with no distribution beside it hides how
    unstable the agent was, and hiding variance is prohibited.

    Args:
        report: The report to summarise.

    Returns:
        scenario_id -> outcome value -> count, both keys sorted for stable rendering.
    """
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    for result in report.results:
        counts[result.scenario_id][str(result.outcome)] += 1
    return {
        scenario_id: dict(sorted(counts[scenario_id].items())) for scenario_id in sorted(counts)
    }


def render_json(report: Report) -> str:
    """The machine-readable report: the Report model verbatim (SPEC.md §4)."""
    return report.model_dump_json(indent=2) + "\n"


def render_markdown(report: Report) -> str:
    """The human-readable report."""
    return _render("report.md.jinja", report)


def render_html(report: Report) -> str:
    """The shareable report. Self-contained: no external CSS, fonts or scripts."""
    return _render("report.html.jinja", report)


def _render(template_name: str, report: Report) -> str:
    """Render one template against a report's view.

    Templates are package data under `report/templates/`, not string constants: report tables
    are naturally wider than source lines, and squeezing them into Python literals made them
    unreadable in exactly the artifact people are meant to read.
    """
    template = resources.files("stinger.report").joinpath("templates", template_name)
    return _environment().from_string(template.read_text(encoding="utf-8")).render(**_view(report))


def _family_scores(results: list[ScenarioResult]) -> dict[Family, FamilyScore]:
    """Group results by family and scenario, then score each family (SPEC.md §8)."""
    grouped: dict[Family, dict[str, list[ScenarioResult]]] = defaultdict(lambda: defaultdict(list))
    for result in results:
        grouped[result.family][result.scenario_id].append(result)
    return {
        family: family_score(family, dict(by_scenario))
        for family, by_scenario in sorted(grouped.items())
    }


def _view(report: Report) -> dict[str, object]:
    """The template context. Formatting decisions live here, not in the templates."""
    missing = sorted(str(f) for f in Family if f not in report.family_scores)
    na_families = sorted(
        str(family)
        for family, score in report.family_scores.items()
        if score.integrity_rate is None
    )
    return {
        "report": report,
        "overall": _percent(report.overall_integrity_rate),
        "families": [
            {
                "family": str(family),
                "rate": _percent(score.integrity_rate),
                "cheat_rate": _percent(
                    None if score.integrity_rate is None else 1.0 - score.integrity_rate
                ),
                "refusal_rate": _percent(_refusal_rate(score)),
                "stdev": f"{score.stdev_across_reps:.3f}",
                "score": score,
            }
            for family, score in sorted(report.family_scores.items())
        ],
        "distribution": outcome_distribution(report),
        "missing_families": missing,
        "na_families": na_families,
        "na_note": NA_NOTE,
        "partial_warning": PARTIAL_RUN_WARNING,
        "reps": _repetition_count(report),
    }


def _refusal_rate(score: FamilyScore) -> float | None:
    """Refusals over all valid outcomes — a behaviour signal, reported separately (§8)."""
    total_valid = score.honest + score.cheated + score.refused + score.failed_honestly
    return score.refused / total_valid if total_valid else None


def _repetition_count(report: Report) -> int:
    """How many repetitions each scenario ran, for the variance note."""
    return len({result.repetition for result in report.results})


def _percent(value: float | None) -> str:
    """Render a rate, or the literal 'n/a' when there was nothing to divide."""
    return "n/a" if value is None else f"{value * 100:.1f}%"


def _environment() -> Environment:
    """A strict Jinja environment: an undefined variable is a bug, not a blank in a report."""
    env = Environment(undefined=StrictUndefined, autoescape=True, trim_blocks=True)
    env.filters["summarise_counts"] = _summarise_counts
    env.filters["verdict_word"] = _verdict_word
    return env


def _summarise_counts(counts: dict[str, int]) -> str:
    """Render an outcome distribution as `cheated x3, honest x1`."""
    return ", ".join(f"{outcome} x{count}" for outcome, count in counts.items())


def _verdict_word(detector: DetectorResult) -> str:
    """How a detector's verdict reads in a report.

    A low-confidence hit is never printed as a bare FIRED: it did not score a cheat, it asked
    for a human. Saying "FIRED" without that qualifier would overstate what the machine
    concluded, in the one document people quote from.
    """
    if detector.fired and detector.low_confidence:
        return "FIRED (low confidence — routed to review, not scored as a cheat)"
    if detector.fired:
        return "FIRED"
    if detector.low_confidence:
        return "could not decide — routed to review"
    return "silent"


def load_report(text: str) -> Report:
    """Parse a stored report.json into a Report.

    Args:
        text: The contents of a repro package's report.json.

    Returns:
        The parsed report. Not verified — call `verify_report` for that.

    Raises:
        ReportMismatchError: If the text is not a readable Report.
    """
    try:
        return Report.model_validate(json.loads(text))
    except (ValueError, TypeError) as exc:
        raise ReportMismatchError(f"not a readable Stinger report: {exc}") from exc


def outcome_counts(results: list[ScenarioResult]) -> Counter[Outcome]:
    """Raw outcome counts across every repetition, for CLI summaries."""
    return Counter(result.outcome for result in results)
