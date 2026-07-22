"""The reproducibility package (SPEC.md §10).

No score is emitted without one. Every `stinger run` writes a self-contained directory:

    repro/<timestamp>/
      report.json  report.html  report.md
      config.resolved.json          the full RunConfig, with its fingerprint
      corpus.lock                   scenario ids + per-scenario hashes + corpus_hash
      rubric.version                RUBRIC_VERSION
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
from stinger.config import RunConfig
from stinger.models import Report
from stinger.report.generate import render_html, render_json, render_markdown
from stinger.scenario.loader import Scenario, corpus_hash, scenario_hash

__all__ = ["RUNS_DIR", "build_corpus_lock", "repro_dir_for", "write_repro_package"]

RUNS_DIR = "runs"
"""Where per-repetition artifacts live inside the package, per SPEC.md §10."""


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
            }
            for scenario in sorted(scenarios, key=lambda s: s.id)
        },
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


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
    directory.mkdir(parents=True, exist_ok=True)
    (directory / RUNS_DIR).mkdir(exist_ok=True)

    (directory / "report.json").write_text(render_json(report), encoding="utf-8")
    (directory / "report.md").write_text(render_markdown(report), encoding="utf-8")
    (directory / "report.html").write_text(render_html(report), encoding="utf-8")
    (directory / "corpus.lock").write_text(build_corpus_lock(scenarios), encoding="utf-8")
    (directory / "rubric.version").write_text(RUBRIC_VERSION + "\n", encoding="utf-8")

    # Ship the corpus inside the package so it is genuinely self-contained: rerun.sh can then
    # re-run against `./corpus` rather than whatever absolute path the original machine used
    # (which would not exist on a fresh clone — a real gap an independent review flagged). The
    # config written into the package points its corpus at that copy.
    corpus_root = _copy_corpus(scenarios, directory / "corpus")
    updates: dict[str, object] = {}
    if corpus_root:
        updates["corpus"] = Path("corpus")
    portable_command = _portable_command(config.agent.command)
    if portable_command != config.agent.command:
        updates["agent"] = config.agent.model_copy(update={"command": portable_command})
    package_config = config.model_copy(update=updates) if updates else config
    (directory / "config.resolved.json").write_text(package_config.resolved_json(), "utf-8")

    rerun = directory / "rerun.sh"
    rerun.write_text(_rerun_script(report, has_corpus=corpus_root is not None), encoding="utf-8")
    rerun.chmod(rerun.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return directory


def _copy_corpus(scenarios: list[Scenario], dest: Path) -> Path | None:
    """Copy every scenario directory into `dest`, returning it (or None if there were none).

    Copied by scenario id so the layout matches a normal corpus root and `discover_scenarios`
    finds them unchanged. Excludes the tool droppings a run leaves behind.
    """
    if not scenarios:
        return None
    dest.mkdir(parents=True, exist_ok=True)
    ignore = shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.pyc", ".DS_Store")
    for scenario in scenarios:
        shutil.copytree(scenario.directory, dest / scenario.id, ignore=ignore, dirs_exist_ok=True)
    return dest


def _portable_command(command: list[str]) -> list[str]:
    """Absolutise argv elements that name existing relative files.

    The generic shell adapter's argv template may point at a script by a path relative to
    the operator's working directory ("demo/agents/strict.py"). Written into the package
    verbatim, rerun.sh step 2 then re-invokes the agent from the package directory, where
    that relative path names nothing — the self-containment fix that copies the corpus in
    never covered the agent command. Elements that are not existing files (program names on
    PATH, flags, the "{prompt}" placeholder) pass through untouched. An absolute path keeps
    step 2 working on the machine that produced the package; a different machine still has
    to supply the agent itself, which step 2's own preamble already states.
    """
    portable: list[str] = []
    for part in command:
        candidate = Path(part)
        if part and "{prompt}" not in part and not candidate.is_absolute() and candidate.is_file():
            portable.append(str(candidate.resolve()))
        else:
            portable.append(part)
    return portable


def _rerun_script(report: Report, *, has_corpus: bool) -> str:
    """The one command that reproduces this run (SPEC.md §10).

    Step 1 is the claim that must hold exactly and needs nothing but this directory. Step 2
    costs an agent invocation (and its credentials) and is where non-determinism legitimately
    appears. A corpus guard makes a missing corpus a clear message rather than an obscure
    crash.
    """
    corpus_guard = (
        ""
        if has_corpus
        else (
            '\nif [ ! -e "$(python -c "import json;'
            "print(json.load(open('config.resolved.json'))['corpus'])\")\" ]; then\n"
            '  echo "step 2 needs the corpus at the path in config.resolved.json; '
            'it is not present here. Step 1 above still verified the scoring offline." >&2\n'
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
# Needs the agent CLI and its credentials, so it is inherently machine-specific. The agent is
# not deterministic; its variation shows up in the per-scenario outcome distribution and the
# family standard deviation the report publishes in full — never as an unexplained change in
# how the evidence was scored. A corpus_hash differing from
# {report.corpus_hash}
# means the corpus changed and the two runs are not comparable.
stinger run --config config.resolved.json "$@"
"""
