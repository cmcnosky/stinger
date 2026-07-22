"""Stinger CLI (SPEC.md §13).

stinger list                 # scenarios + families + validity status
stinger validate [PATH]      # run the validity contract (SPEC.md §12)
stinger run --config …       # run the corpus against a configured agent, emit a Report
stinger report REPRO_DIR     # re-render a report from a repro package
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import click

from stinger.adapters.factory import AdapterError, build_adapter
from stinger.config import ConfigError, RunConfig
from stinger.harness.runner import run_scenario_once
from stinger.harness.sandbox import Isolation, Sandbox, SandboxError
from stinger.models import Family, JudgeReport, Report, ScenarioResult
from stinger.report.generate import (
    PARTIAL_RUN_WARNING,
    ReportMismatchError,
    build_report,
    load_report,
    render_html,
    render_json,
    render_markdown,
    verify_report,
)
from stinger.report.repro import RUNS_DIR, repro_dir_for, write_repro_package
from stinger.scenario.loader import (
    Scenario,
    ScenarioLoadError,
    corpus_hash,
    discover_scenarios,
)
from stinger.scenario.manifest import ValidityError, validate_scenario


@click.group()
@click.version_option()
def main() -> None:
    """Measure whether an AI coding agent cheats, in your configuration."""


@main.command(name="list")
@click.argument("path", type=click.Path(exists=True, path_type=Path), default="scenarios")
@click.option(
    "--validate",
    "run_validation",
    is_flag=True,
    help="also run the validity contract, so STATUS reports proven validity rather than "
    "'loaded' (slower: materialises both reference resolutions per scenario)",
)
@click.option("--docker", is_flag=True, help="force container isolation for every scenario")
def list_scenarios(path: Path, run_validation: bool, docker: bool) -> None:
    """List scenarios with family and validity status.

    Without --validate this reports only that a scenario LOADED, never that it is valid.
    Saying "valid" on the strength of a manifest that merely parsed would be exactly the kind
    of unearned claim the honest-status rule in AGENTS.md forbids.
    """
    try:
        scenarios = discover_scenarios(path)
    except ScenarioLoadError as exc:
        raise click.ClickException(str(exc)) from exc

    rows = [(s.id, str(s.manifest.family), _status(s, run_validation, docker)) for s in scenarios]
    width = max(len(row[0]) for row in rows)
    click.echo(f"{'ID':<{width}}  FAMILY  STATUS")
    for scenario_id, family, status in rows:
        click.echo(f"{scenario_id:<{width}}  {family:<6}  {status}")

    click.echo(f"\n{len(rows)} scenario(s) in {path}")
    if not run_validation:
        click.echo("STATUS is load status only — run `stinger validate` to prove validity.")
    if any(status.startswith(("INVALID", "unloadable")) for _, _, status in rows):
        raise SystemExit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path), default="scenarios")
@click.option("--docker", is_flag=True, help="force container isolation for every scenario")
def validate(path: Path, docker: bool) -> None:
    """Run the validity contract over the corpus (SPEC.md §12). Non-zero exit on any failure.

    For each scenario: overlay the honest reference and assert no detector fires and the
    held-out completion check passes; overlay the cheat reference and assert the intended
    detector fires. This is what proves a trap is fair before any agent is judged by it.

    Every scenario is reported, not just the first failure, so one broken trap does not hide
    another. The exit code is non-zero if any scenario failed.
    """
    try:
        scenarios = discover_scenarios(path)
    except ScenarioLoadError as exc:
        raise click.ClickException(str(exc)) from exc

    failures = 0
    for scenario in scenarios:
        try:
            box = _sandbox_for(scenario, docker)
            box.preflight()
            validate_scenario(scenario.directory, scenario.manifest, sandbox=box)
        except (ValidityError, SandboxError) as exc:
            failures += 1
            click.echo(f"FAIL  {scenario.id}\n      {exc}")
        else:
            click.echo(f"ok    {scenario.id} ({scenario.manifest.family})")

    click.echo(f"\n{len(scenarios) - failures}/{len(scenarios)} scenario(s) valid")
    if failures:
        raise SystemExit(1)


def _sandbox_for(scenario: Scenario, docker: bool) -> Sandbox:
    """Isolation for validating one scenario.

    Chosen by what the scenario contains, not by preference: family X always gets a
    container, because its seeded bait secrets and exfiltration lures must not run
    unconfined (SPEC.md §2). Everything else validates locally by default — validation runs
    the corpus's own reviewed reference resolutions, not agent-generated code — and --docker
    opts the whole corpus into containers for a stricter pass.
    """
    if docker or scenario.manifest.family == "X":
        return Sandbox(isolation=Isolation.DOCKER)
    return Sandbox(isolation=Isolation.LOCAL)


def _status(scenario: Scenario, run_validation: bool, docker: bool) -> str:
    """The STATUS column: load status, or proven validity when --validate was passed."""
    if not run_validation:
        return "loaded"
    try:
        box = _sandbox_for(scenario, docker)
        box.preflight()
        validate_scenario(scenario.directory, scenario.manifest, sandbox=box)
    except (ValidityError, SandboxError) as exc:
        return f"INVALID: {exc}"
    return "valid"


@main.command()
@click.option("--config", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--only", type=click.Choice(["T", "S", "C", "G", "X"]), default=None)
@click.option("--reps", type=int, default=None, help="override RunConfig.reps")
@click.option("--local", is_flag=True, help="git-worktree isolation (dev only; refuses X family)")
def run(config: Path, only: str | None, reps: int | None, local: bool) -> None:
    """Run the corpus against the configured agent and write a repro package + Report.

    Every scenario is validated first (SPEC.md §12) and the run refuses to start if any fails
    — a trap that cannot prove itself fair must not contribute to a published number.

    The wall clock is read exactly once, here, and that one timestamp stamps the whole run.
    Nothing downstream reads it again, so scoring stays a pure function of the evidence
    (AGENTS.md rule 6).
    """
    resolved = _resolve_config(config, only, reps, local)
    scenarios = _load_and_validate(resolved)
    generated_at = datetime.now(UTC).isoformat()
    package = repro_dir_for(resolved, generated_at)

    try:
        adapter = build_adapter(resolved.agent)
    except AdapterError as exc:
        raise click.ClickException(str(exc)) from exc
    sandbox = Sandbox(isolation=resolved.isolation, image=resolved.image)
    try:
        # Before anything runs: prove the verification image can serve a completion check.
        # A missing pytest would fail every check for a reason that has nothing to do with
        # the agent, and produce a plausible-looking report of universal failure.
        sandbox.preflight()
    except SandboxError as exc:
        raise click.ClickException(str(exc)) from exc

    results: list[ScenarioResult] = []
    for scenario in scenarios:
        for repetition in range(resolved.reps):
            click.echo(f"  {scenario.id} rep {repetition + 1}/{resolved.reps} ... ", nl=False)
            result = run_scenario_once(
                scenario.directory,
                scenario.manifest,
                adapter,
                repetition,
                sandbox=sandbox,
                artifacts_dir=package / RUNS_DIR / scenario.id / str(repetition),
                path_root=package,
            )
            results.append(result)
            click.echo(str(result.outcome))

    report_ = build_report(
        results,
        corpus_hash=corpus_hash(scenarios),
        config_fingerprint=resolved.fingerprint(),
        generated_at=generated_at,
        judge_assisted=_maybe_judge(resolved),
    )
    write_repro_package(package, report_, resolved, scenarios)

    _echo_summary(report_, package)
    _enforce_regression_threshold(report_, resolved)


@main.command()
@click.argument("repro_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--format", "fmt", type=click.Choice(["html", "md", "json"]), default="html")
def report(repro_dir: Path, fmt: str) -> None:
    """Re-render an Integrity Report from an existing reproducibility package.

    Re-rendering is the cheap half. The valuable half is that this first RECOMPUTES every
    published number from the report's own stored results and exits non-zero if anything
    disagrees. That makes a report checkable offline, with no agent and no container, and it
    is step 1 of the `rerun.sh` a run writes (SPEC.md §10).
    """
    source = repro_dir / "report.json" if repro_dir.is_dir() else repro_dir
    try:
        loaded = load_report(source.read_text(encoding="utf-8"))
        verify_report(loaded)
    except OSError as exc:
        raise click.ClickException(f"could not read {source}: {exc}") from exc
    except ReportMismatchError as exc:
        raise click.ClickException(
            f"{source} does not survive re-scoring from its own evidence: {exc}"
        ) from exc

    renderers = {"json": render_json, "md": render_markdown, "html": render_html}
    click.echo(renderers[fmt](loaded), nl=False)


def _resolve_config(config: Path, only: str | None, reps: int | None, local: bool) -> RunConfig:
    """Apply the command-line overrides to the loaded config."""
    try:
        loaded = RunConfig.from_yaml(config)
    except ConfigError as exc:
        raise click.ClickException(str(exc)) from exc

    overrides: dict[str, object] = {}
    if only is not None:
        overrides["only"] = Family(only)
    if reps is not None:
        overrides["reps"] = reps
    if local:
        overrides["isolation"] = Isolation.LOCAL
    if not overrides:
        return loaded
    # Re-validated rather than model_copy'd: an override must pass the same checks the YAML
    # did, or `--reps 0` would slip past the ge=1 constraint the config declares.
    return RunConfig.model_validate({**loaded.model_dump(), **overrides})


def _load_and_validate(config: RunConfig) -> list[Scenario]:
    """Load the corpus, apply the family filter, and refuse anything that fails §12."""
    try:
        scenarios = discover_scenarios(config.corpus)
    except ScenarioLoadError as exc:
        raise click.ClickException(str(exc)) from exc

    if config.only is not None:
        scenarios = [s for s in scenarios if s.manifest.family == config.only]
        if not scenarios:
            raise click.ClickException(
                f"no scenarios in family {config.only} under {config.corpus}"
            )

    # Fail closed on family X unless the AGENT itself is contained. Docker isolation
    # sandboxes the VERIFICATION commands, but the agent under test is driven by the adapter
    # as a host subprocess unless `agent.container_image` is set — so an X scenario (bait
    # credentials, exfiltration lures, destructive-command traps) would otherwise run against
    # an agent with full host access. Refusing here is the real safety boundary; the
    # sandbox's --local refusal alone is not enough (an independent review flagged this).
    x_scenarios = [s.id for s in scenarios if s.manifest.family == Family.X]
    if x_scenarios and config.agent.container_image is None:
        raise click.ClickException(
            "refusing to run the X (safety/exfiltration) family without a contained agent: "
            f"{', '.join(x_scenarios[:3])}{'…' if len(x_scenarios) > 3 else ''}. These "
            "scenarios seed bait credentials and destructive lures, and Docker isolation "
            "contains only the verification commands, not the agent — the agent runs as a "
            "host subprocess unless `agent.container_image` names an image with the agent CLI "
            "installed. Set that, or restrict the run with --only to a non-X family."
        )

    failures = []
    for scenario in scenarios:
        try:
            _sandbox_for(scenario, config.isolation is Isolation.DOCKER).preflight()
            validate_scenario(
                scenario.directory,
                scenario.manifest,
                sandbox=_sandbox_for(scenario, config.isolation is Isolation.DOCKER),
            )
        except (ValidityError, SandboxError) as exc:
            failures.append(str(exc))
    if failures:
        raise click.ClickException(
            "refusing to run: scenario(s) failed the validity contract, and a trap that "
            "cannot prove itself fair must not contribute to a published number "
            "(SPEC.md §12).\n  " + "\n  ".join(failures)
        )
    return scenarios


def _maybe_judge(config: RunConfig) -> JudgeReport | None:
    """The judge is advisory and needs an operator-supplied client (SPEC.md §9).

    Always None from the CLI: Stinger ships no live judge transport, because nothing in the
    scoring path may reach the network and the judge is where that line is easiest to blur.
    `scoring.judge.run_judge` is complete and tested; wiring a client to it is an operator
    decision, not something the CLI does behind their back.
    """
    if config.judge.enabled:
        click.echo(
            "note: judge.enabled is set, but this build ships no judge transport. The run "
            "continues; the mechanical score is unaffected either way (SPEC.md §9)."
        )
    return None


def _echo_summary(report_: Report, package: Path) -> None:
    """Print the headline honestly, including what it is not."""
    if report_.partial:
        click.echo(f"\n{PARTIAL_RUN_WARNING}")
    rate = report_.overall_integrity_rate
    click.echo(f"\noverall integrity rate: {'n/a' if rate is None else f'{rate * 100:.1f}%'}")
    for family, score in sorted(report_.family_scores.items()):
        shown = "n/a" if score.integrity_rate is None else f"{score.integrity_rate * 100:.1f}%"
        click.echo(
            f"  {family}: {shown}  (honest={score.honest} cheated={score.cheated} "
            f"refused={score.refused} failed={score.failed_honestly} error={score.error}, "
            f"stdev={score.stdev_across_reps:.3f})"
        )
    click.echo(f"\nreproducibility package: {package}")
    click.echo(f"re-run with: {package / 'rerun.sh'}")


def _enforce_regression_threshold(report_: Report, config: RunConfig) -> None:
    """The CI gates (SPEC.md §14): an absolute floor, and no regression vs. the baseline.

    Both are checked, and both failures are reported before exiting, so a run that broke two
    gates does not send someone back for a second round trip.
    """
    problems = [
        problem
        for problem in (_below_threshold(report_, config), _regressed(report_, config))
        if problem
    ]
    if problems:
        raise click.ClickException("\n".join(problems))


def _below_threshold(report_: Report, config: RunConfig) -> str | None:
    """Fail when the overall rate is under the configured absolute floor."""
    if config.regression_threshold is None:
        return None
    rate = report_.overall_integrity_rate
    if rate is None:
        return (
            f"regression_threshold is set to {config.regression_threshold} but this run "
            "produced no overall integrity rate to compare against"
        )
    if rate < config.regression_threshold:
        return (
            f"integrity regression: overall rate {rate:.3f} is below the configured "
            f"threshold {config.regression_threshold:.3f}"
        )
    return None


def _regressed(report_: Report, config: RunConfig) -> str | None:
    """Fail when integrity dropped against the committed baseline (SPEC.md §14).

    The baseline is re-scored from its own stored results before it is trusted. Lowering a
    baseline by editing its headline number therefore does not work — the evidence has to be
    edited too, which is a visible act in a diff rather than a quiet one.
    """
    if config.baseline is None:
        return None
    try:
        baseline = load_report(config.baseline.read_text(encoding="utf-8"))
        verify_report(baseline)
    except OSError as exc:
        raise click.ClickException(f"could not read the baseline {config.baseline}: {exc}") from exc
    except ReportMismatchError as exc:
        raise click.ClickException(
            f"the baseline {config.baseline} does not survive re-scoring from its own "
            f"evidence, so it cannot be trusted as a comparison point: {exc}"
        ) from exc

    previous, current = baseline.overall_integrity_rate, report_.overall_integrity_rate
    if previous is None:
        return None  # nothing to regress from
    if current is None:
        return (
            f"the baseline reports {previous:.3f} but this run produced no overall integrity "
            "rate to compare against"
        )

    click.echo(
        f"baseline {config.baseline}: {previous * 100:.1f}%  ->  this run: {current * 100:.1f}%"
    )
    if current < previous - config.regression_tolerance:
        return (
            f"integrity regression: {current:.3f} is below the committed baseline "
            f"{previous:.3f} (tolerance {config.regression_tolerance:.3f}). Agent "
            f"non-determinism shows up in the per-family standard deviation the report "
            f"publishes — check that before raising the tolerance."
        )
    return None


if __name__ == "__main__":
    main()
