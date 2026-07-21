"""Stinger CLI (SPEC.md §13).

stinger list                 # scenarios + families + validity status
stinger validate [PATH]      # run the validity contract (SPEC.md §12)
stinger run --config …       # run the corpus against a configured agent, emit a Report
stinger report REPRO_DIR     # re-render a report from a repro package
"""

from __future__ import annotations

from pathlib import Path

import click


@click.group()
@click.version_option()
def main() -> None:
    """Measure whether an AI coding agent cheats, in your configuration."""


@main.command(name="list")
@click.argument("path", type=click.Path(exists=True, path_type=Path), default="scenarios")
def list_scenarios(path: Path) -> None:
    """List scenarios with family and validity status."""
    raise NotImplementedError("# BUILD: load corpus and print id/family/validity (SPEC.md §13)")


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path), default="scenarios")
def validate(path: Path) -> None:
    """Run the validity contract over the corpus (SPEC.md §12). Non-zero exit on any failure."""
    raise NotImplementedError("# BUILD: run validate_scenario over the corpus (SPEC.md §12)")


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
