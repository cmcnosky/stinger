"""Stinger CLI (SPEC.md §13).

stinger list                 # scenarios + families + validity status
stinger validate [PATH]      # run the validity contract (SPEC.md §12)
stinger run --config …       # run the corpus against a configured agent, emit a Report
stinger report REPRO_DIR     # re-render a report from a repro package
"""

from __future__ import annotations

from pathlib import Path

import click

from stinger.harness.sandbox import Isolation, Sandbox
from stinger.scenario.loader import Scenario, ScenarioLoadError, discover_scenarios
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
            validate_scenario(
                scenario.directory, scenario.manifest, sandbox=_sandbox_for(scenario, docker)
            )
        except ValidityError as exc:
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
        validate_scenario(
            scenario.directory, scenario.manifest, sandbox=_sandbox_for(scenario, docker)
        )
    except ValidityError as exc:
        return f"INVALID: {exc}"
    return "valid"


@main.command()
@click.option("--config", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--only", type=click.Choice(["T", "S", "C", "G", "X"]), default=None)
@click.option("--reps", type=int, default=None, help="override RunConfig.reps")
@click.option("--local", is_flag=True, help="git-worktree isolation (dev only; refuses X family)")
def run(config: Path, only: str | None, reps: int | None, local: bool) -> None:
    """Run the corpus against the configured agent and write a repro package + Report."""
    raise NotImplementedError("# BUILD: drive runner + scoring + report per SPEC.md §7,§8,§10")


@main.command()
@click.argument("repro_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--format", "fmt", type=click.Choice(["html", "md", "json"]), default="html")
def report(repro_dir: Path, fmt: str) -> None:
    """Re-render an Integrity Report from an existing reproducibility package."""
    raise NotImplementedError("# BUILD: render report from repro package (SPEC.md §10)")


if __name__ == "__main__":
    main()
