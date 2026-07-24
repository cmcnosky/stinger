"""The reproducibility package (SPEC.md §10).

No score is emitted without one. Every `stinger run` writes a self-contained directory:

    repro/<timestamp>/
      report.json  report.html  report.md
      config.resolved.json          the full RunConfig, with its fingerprint
      corpus.lock                   scenario ids + per-scenario hashes + corpus_hash
      rubric.version                RUBRIC_VERSION
      benchmark.protocol.version    benchmark runs only
      runs/<scenario>/<rep>/        transcript.txt, before.diff, after.diff, artifacts
      rerun.sh                      one command that reproduces this run

`rerun.sh` has two steps, because reproducibility here has two halves that are worth keeping
apart. The first recomputes the published numbers from the stored evidence: deterministic,
agent-free, and the part that must hold exactly. The second re-invokes the agent over the
pinned corpus and config, where the agent's own non-determinism shows up as variance in the
distribution — never as an unexplained change in how the evidence was scored.
"""

from __future__ import annotations

import json
import shutil
import stat
from pathlib import Path

from stinger import RUBRIC_VERSION
from stinger.benchmark.protocol import BenchmarkSplit
from stinger.config import RunConfig
from stinger.models import Report
from stinger.report.generate import render_html, render_json, render_markdown
from stinger.scenario.loader import Scenario, corpus_hash, scenario_hash

__all__ = [
    "RUNS_DIR",
    "SEALED_REPRO_MARKER",
    "build_corpus_lock",
    "prepare_repro_package",
    "repro_dir_for",
    "write_repro_package",
]

RUNS_DIR = "runs"
"""Where per-repetition artifacts live inside the package, per SPEC.md §10."""

SEALED_REPRO_MARKER = "SEALED_BENCHMARK_EVIDENCE_DO_NOT_UPLOAD"
"""Marker consumed by CI and escrow verification to block public disclosure."""

_SEALED_CORPUS_PLACEHOLDER = Path("SEALED_CORPUS_REQUIRED_FROM_ESCROW")
_SEALED_CREDENTIAL_PLACEHOLDER = Path("SEALED_CREDENTIAL_MOUNT_REQUIRED")


def repro_dir_for(config: RunConfig, timestamp: str) -> Path:
    """The package directory for a run, named by its timestamp.

    Args:
        config: The resolved run configuration, supplying `output_dir`.
        timestamp: An RFC3339 timestamp, passed in rather than read here so the whole run is
            stamped once (AGENTS.md rule 6).

    Returns:
        `<output_dir>/<timestamp>`, with characters that are awkward in paths replaced.
    """
    safe = timestamp.replace(":", "-").replace("+", "-")
    return config.output_dir / safe


def build_corpus_lock(scenarios: list[Scenario]) -> str:
    """The corpus lock: what exactly was measured (SPEC.md §10).

    Records each scenario's id and content hash alongside the corpus hash, so a report can be
    tied to the precise corpus that produced it and any later edit to a trap is visible as a
    changed hash.

    Args:
        scenarios: The loaded corpus, in any order.

    Returns:
        Canonical JSON, sorted, newline-terminated.
    """
    payload = {
        "corpus_hash": corpus_hash(scenarios),
        "scenarios": {
            scenario.id: {
                "family": str(scenario.manifest.family),
                "hash": scenario_hash(scenario),
                "benchmark_split": str(scenario.manifest.benchmark_split),
                "scenario_version": scenario.manifest.scenario_version,
                "cluster_id": scenario.manifest.cluster_id,
            }
            for scenario in sorted(scenarios, key=lambda s: s.id)
        },
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def prepare_repro_package(directory: Path, scenarios: list[Scenario]) -> bool:
    """Create the disclosure guard before any agent or harness output is written.

    A run can fail before :func:`write_repro_package` assembles its final report. Marking a
    sealed package only at that final step would leave partial transcripts uploadable by a
    generic ``if: always()`` CI artifact step. Callers therefore invoke this immediately
    after choosing the package path, before adapter construction or execution.

    Args:
        directory: Package path selected for the run.
        scenarios: Complete loaded scenario set.

    Returns:
        ``True`` when the run is sealed and the marker was written.

    Raises:
        ValueError: If sealed and non-sealed scenarios are mixed or a pre-existing copied
            corpus makes the directory unsafe.
    """
    splits = {scenario.manifest.benchmark_split for scenario in scenarios}
    sealed = BenchmarkSplit.SEALED in splits
    if sealed and splits != {BenchmarkSplit.SEALED}:
        raise ValueError("a reproducibility package cannot mix sealed and non-sealed scenarios")
    if sealed and (directory / "corpus").exists():
        raise ValueError("refusing a sealed reproducibility package because corpus/ already exists")
    if sealed:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / SEALED_REPRO_MARKER).write_text(
            "Active sealed benchmark evidence. Do not upload or publish this directory.\n",
            encoding="utf-8",
        )
    return sealed


def write_repro_package(
    directory: Path,
    report: Report,
    config: RunConfig,
    scenarios: list[Scenario],
) -> Path:
    """Write the full package (SPEC.md §10).

    Per-repetition artifacts are expected to already live under `directory/runs/...`; the
    runner writes them there as each repetition finishes, so a run that dies partway still
    leaves its evidence behind.

    Args:
        directory: The package directory, created if absent.
        report: The Integrity Report to publish.
        config: The resolved configuration that produced it.
        scenarios: The corpus that was measured.

    Returns:
        The package directory.
    """
    sealed = prepare_repro_package(directory, scenarios)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / RUNS_DIR).mkdir(exist_ok=True)

    (directory / "report.json").write_text(render_json(report), encoding="utf-8")
    (directory / "report.md").write_text(render_markdown(report), encoding="utf-8")
    (directory / "report.html").write_text(render_html(report), encoding="utf-8")
    (directory / "corpus.lock").write_text(build_corpus_lock(scenarios), encoding="utf-8")
    (directory / "rubric.version").write_text(RUBRIC_VERSION + "\n", encoding="utf-8")
    if report.benchmark_protocol_version is not None:
        (directory / "benchmark.protocol.version").write_text(
            report.benchmark_protocol_version + "\n",
            encoding="utf-8",
        )

    # Development/retired scenarios may travel with ordinary repro packages. Active sealed
    # scenarios never do: their answer-bearing source belongs only in the access-controlled
    # escrow bundle. The local run evidence is marked so generic CI also refuses to upload
    # transcripts/diffs that may reveal task material.
    corpus_root = None if sealed else _copy_corpus(scenarios, directory / "corpus")
    updates: dict[str, object] = {}
    if sealed:
        updates["corpus"] = _SEALED_CORPUS_PLACEHOLDER
    elif corpus_root:
        updates["corpus"] = Path("corpus")
    agent_updates: dict[str, object] = {}
    if sealed and config.agent.credential_mount is not None:
        agent_updates["credential_mount"] = _SEALED_CREDENTIAL_PLACEHOLDER
    if agent_updates:
        updates["agent"] = config.agent.model_copy(update=agent_updates)
    package_config = config.model_copy(update=updates) if updates else config
    if package_config.fingerprint() != config.fingerprint():
        raise ValueError("portable repro configuration changed the run fingerprint")
    (directory / "config.resolved.json").write_text(package_config.resolved_json(), "utf-8")

    rerun = directory / "rerun.sh"
    rerun.write_text(
        _rerun_script(report, has_corpus=corpus_root is not None, sealed=sealed),
        encoding="utf-8",
    )
    rerun.chmod(rerun.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return directory


def _copy_corpus(scenarios: list[Scenario], dest: Path) -> Path | None:
    """Copy every scenario directory into `dest`, returning it (or None if there were none).

    Copied by scenario id so the layout matches a normal corpus root and `discover_scenarios`
    finds them unchanged. Excludes the tool droppings a run leaves behind.
    """
    if not scenarios:
        return None
    if any(scenario.manifest.benchmark_split is BenchmarkSplit.SEALED for scenario in scenarios):
        raise ValueError("active sealed scenarios must never be copied into an ordinary repro")
    dest.mkdir(parents=True, exist_ok=True)
    ignore = shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.pyc", ".DS_Store")
    for scenario in scenarios:
        shutil.copytree(scenario.directory, dest / scenario.id, ignore=ignore, dirs_exist_ok=True)
    return dest


def _rerun_script(report: Report, *, has_corpus: bool, sealed: bool) -> str:
    """The one command that reproduces this run (SPEC.md §10).

    Step 1 is the claim that must hold exactly and needs nothing but this directory. Step 2
    costs an agent invocation (and its credentials) and is where non-determinism legitimately
    appears. A corpus guard makes a missing corpus a clear message rather than an obscure
    crash.
    """
    missing_reason = (
        "the active sealed corpus is available only through the access-controlled escrow bundle"
        if sealed
        else "the corpus is not present here"
    )
    corpus_guard = (
        ""
        if has_corpus
        else (
            '\nif [ ! -e "$(python -c "import json;'
            "print(json.load(open('config.resolved.json'))['corpus'])\")\" ]; then\n"
            '  echo "step 2 needs the corpus at the path in config.resolved.json; '
            f'{missing_reason}. Step 1 above still verified the scoring offline." >&2\n'
            "  exit 0\nfi"
        )
    )
    return f"""#!/usr/bin/env bash
# Reproduce this Stinger run. Generated by stinger; safe to read before running.
#
# This run:
#   rubric version     {report.rubric_version}
#   corpus hash        {report.corpus_hash}
#   config fingerprint {report.config_fingerprint}
#   generated at       {report.generated_at}
#   overall integrity  {report.overall_integrity_rate}
set -euo pipefail
cd "$(dirname "$0")"

echo "==> 1/2 rescore — recompute this report's numbers from its own stored evidence"
# Deterministic, agent-free, offline. Exits non-zero if any published number disagrees with a
# recomputation from the stored results, if any outcome does not follow from its own detector
# evidence, or if this build implements a different rubric version. This is the half of
# reproducibility that must hold exactly, and it needs nothing but this directory.
stinger report . --format md >/dev/null
echo "    ok: numbers and outcomes reproduce from the stored evidence"
{corpus_guard}
echo "==> 2/2 rerun — re-invoke the agent over the same corpus and configuration"
# Needs the agent CLI and its credentials, so it is inherently machine-specific. A relative
# shell-adapter command is resolved from this package directory. Supply the same agent build
# here (or use the pinned benchmark agent container); silently rewriting the command to an
# absolute path would change the configuration fingerprint this report binds.
# The agent is not deterministic; its variation shows up in the outcome distribution and the
# family standard deviation the report publishes in full — never as an unexplained change in
# how the evidence was scored. A corpus_hash differing from
# {report.corpus_hash}
# means the corpus changed and the two runs are not comparable.
stinger run --config config.resolved.json "$@"
"""
