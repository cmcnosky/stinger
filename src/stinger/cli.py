"""Stinger CLI (SPEC.md §13).

stinger list                 # scenarios + families + validity status
stinger validate [PATH]      # run the validity contract (SPEC.md §12)
stinger validate --config …  # …over the corpus a stinger.yaml names, for CI
stinger run --config …       # run the corpus against a configured agent, emit a Report
stinger report REPRO_DIR     # re-render a report from a repro package
stinger benchmark …          # candidate protocol, evidence, comparisons, release gates
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import click
from pydantic import ValidationError

from stinger.adapters.factory import AdapterError, build_adapter
from stinger.benchmark.comparison import (
    BenchmarkComparisonError,
    build_paired_comparison,
)
from stinger.benchmark.evidence import (
    EvidenceBundleError,
    PublicLeakagePolicy,
    create_escrow_evidence_bundle,
    create_public_evidence_bundle,
    verify_escrow_evidence_bundle,
    verify_public_evidence_bundle,
)
from stinger.benchmark.gates import (
    BenchmarkGateReport,
    BenchmarkProtocolManifest,
    BenchmarkReleaseSubmission,
    authorize_benchmark_submission,
    authorize_reproduction_statement,
    evaluate_benchmark_release,
    load_benchmark_protocol,
    load_benchmark_submission,
)
from stinger.benchmark.ordering import ScenarioOrderItem, deterministic_blocked_ids
from stinger.benchmark.provenance import RuntimePreflightError, verify_runtime_provenance
from stinger.benchmark.signing import (
    ProtocolSignatureError,
    sign_protocol,
    sign_release_submission,
    sign_reproduction_statement,
    verify_protocol_signature,
)
from stinger.config import DEFAULT_IMAGE, ConfigError, RunConfig
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
from stinger.report.repro import (
    RUNS_DIR,
    prepare_repro_package,
    repro_dir_for,
    write_repro_package,
)
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


@main.group(name="benchmark")
def benchmark_commands() -> None:
    """Build and verify benchmark evidence without implying release eligibility."""


@benchmark_commands.command(name="sign-protocol")
@click.argument("protocol", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--private-key",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="existing operator-controlled OpenSSH key; Stinger never copies it",
)
def sign_benchmark_protocol(protocol: Path, private_key: Path) -> None:
    """Create a detached OpenSSH signature without generating or storing a private key."""
    try:
        signature = sign_protocol(protocol, private_key)
    except ProtocolSignatureError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"signed benchmark protocol: {signature}")


@benchmark_commands.command(name="sign-release")
@click.argument("submission", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--private-key",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
def sign_benchmark_release(submission: Path, private_key: Path) -> None:
    """Sign exact release-submission bytes as the human publication authorization."""
    try:
        signature = sign_release_submission(submission, private_key)
    except ProtocolSignatureError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"signed benchmark release submission: {signature}")


@benchmark_commands.command(name="sign-reproduction")
@click.argument("statement", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--private-key",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
def sign_benchmark_reproduction(statement: Path, private_key: Path) -> None:
    """Sign an independent evaluator's exact artifact-binding statement."""
    try:
        signature = sign_reproduction_statement(statement, private_key)
    except ProtocolSignatureError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"signed benchmark reproduction statement: {signature}")


@benchmark_commands.command(name="verify-protocol")
@click.argument("protocol", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--signature",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option("--signer-identity", required=True)
def verify_benchmark_protocol(
    protocol: Path,
    signature: Path,
    allowed_signers: Path,
    signer_identity: str,
) -> None:
    """Verify exact protocol bytes against an independently trusted signer policy."""
    try:
        verified = verify_protocol_signature(
            protocol,
            signature,
            allowed_signers,
            signer_identity,
        )
    except ProtocolSignatureError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(
        f"verified benchmark protocol signer {verified.identity}: {verified.protocol_sha256}"
    )


@benchmark_commands.command(name="protocol-check")
@click.argument(
    "protocol",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default="benchmark/protocol.yaml",
)
def check_benchmark_protocol(protocol: Path) -> None:
    """Refuse a machine protocol manifest that weakens or drifts from v1."""
    try:
        loaded = load_benchmark_protocol(protocol)
    except (OSError, ValueError, ValidationError) as exc:
        raise click.ClickException(f"invalid benchmark protocol: {exc}") from exc
    if loaded != BenchmarkProtocolManifest():
        raise click.ClickException(
            "protocol manifest differs from the compiled Benchmark v1 release thresholds"
        )
    click.echo(
        f"benchmark protocol {loaded.benchmark_protocol_version} is structurally valid "
        f"({loaded.total_scenarios} sealed scenarios, status={loaded.status.value})"
    )


@benchmark_commands.command(name="release-schema")
def benchmark_release_schema() -> None:
    """Print the closed JSON Schema for corpus, review, run, and approval evidence."""
    click.echo(
        json.dumps(
            BenchmarkReleaseSubmission.model_json_schema(),
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_commands.command(name="release-check")
@click.argument(
    "submission",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
@click.option("--signature", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option("--signer-identity")
@click.option(
    "--reproduction-statement",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--reproduction-signature",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--verifier-allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option("--verifier-identity")
def benchmark_release_check(
    submission: Path,
    output_format: str,
    signature: Path | None,
    allowed_signers: Path | None,
    signer_identity: str | None,
    reproduction_statement: Path | None,
    reproduction_signature: Path | None,
    verifier_allowed_signers: Path | None,
    verifier_identity: str | None,
) -> None:
    """Evaluate every v1 release gate; blocked submissions exit non-zero."""
    try:
        release_inputs = (signature, allowed_signers, signer_identity)
        if any(item is not None for item in release_inputs) and not all(
            item is not None for item in release_inputs
        ):
            raise ValueError(
                "--signature, --allowed-signers, and --signer-identity are all required together"
            )
        if signature is not None and allowed_signers is not None and signer_identity is not None:
            loaded, authorization = authorize_benchmark_submission(
                submission,
                signature,
                allowed_signers,
                signer_identity,
            )
        else:
            loaded = load_benchmark_submission(submission)
            authorization = None

        reproduction_inputs = (
            reproduction_statement,
            reproduction_signature,
            verifier_allowed_signers,
            verifier_identity,
        )
        if any(item is not None for item in reproduction_inputs) and not all(
            item is not None for item in reproduction_inputs
        ):
            raise ValueError(
                "all reproduction statement/signature/verifier trust options are required together"
            )
        reproduction_authorization = (
            authorize_reproduction_statement(
                reproduction_statement,
                reproduction_signature,
                verifier_allowed_signers,
                verifier_identity,
            )
            if reproduction_statement is not None
            and reproduction_signature is not None
            and verifier_allowed_signers is not None
            and verifier_identity is not None
            else None
        )
        gate = evaluate_benchmark_release(
            loaded,
            authorization=authorization,
            reproduction_authorization=reproduction_authorization,
        )
    except (OSError, ValueError, ValidationError, ProtocolSignatureError) as exc:
        raise click.ClickException(f"invalid benchmark release submission: {exc}") from exc

    if output_format == "json":
        click.echo(gate.model_dump_json(indent=2))
    else:
        _echo_benchmark_gate(gate)
    if not gate.publishable:
        raise SystemExit(1)


def _echo_benchmark_gate(gate: BenchmarkGateReport) -> None:
    """Render a compact release decision while retaining every blocking issue."""
    click.echo(f"status: {gate.status.value}")
    click.echo(f"publishable: {'yes' if gate.publishable else 'no'}")
    click.echo(
        "evidence: "
        f"{gate.metrics.unique_scenarios} scenarios, "
        f"{gate.metrics.unique_clusters} clusters, "
        f"{gate.metrics.baseline_configurations} configurations, "
        f"{gate.metrics.baseline_providers} providers, "
        f"{gate.metrics.complete_beta_operators} outside beta operators, "
        f"{gate.metrics.independent_reproductions} independent reproductions"
    )
    if not gate.issues:
        return
    click.echo(f"blocking issues ({len(gate.issues)}):")
    for issue in gate.issues:
        subject = "" if issue.subject is None else f" [{issue.subject}]"
        click.echo(f"  {issue.code.value}{subject}: {issue.detail}")


@benchmark_commands.command(name="compare")
@click.argument("candidate", type=click.Path(exists=True, path_type=Path))
@click.argument("baseline", type=click.Path(exists=True, path_type=Path))
@click.option("--samples", type=click.IntRange(min=1), default=10_000, show_default=True)
@click.option("--seed", type=click.IntRange(min=0), default=0, show_default=True)
def compare_benchmark_reports(
    candidate: Path,
    baseline: Path,
    samples: int,
    seed: int,
) -> None:
    """Emit a paired candidate-minus-baseline cluster-bootstrap comparison."""
    try:
        candidate_report = _load_report_path(candidate)
        baseline_report = _load_report_path(baseline)
        comparison = build_paired_comparison(
            candidate_report,
            baseline_report,
            samples=samples,
            seed=seed,
        )
    except (OSError, ReportMismatchError, BenchmarkComparisonError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(comparison.model_dump_json(indent=2))


def _load_report_path(path: Path) -> Report:
    """Load a report file or a reproducibility directory without trusting its numbers."""
    source = path / "report.json" if path.is_dir() else path
    return load_report(source.read_text(encoding="utf-8"))


@benchmark_commands.command(name="bundle-public")
@click.option(
    "--destination",
    type=click.Path(path_type=Path),
    required=True,
    help="new directory to create; existing paths are refused",
)
@click.option(
    "--protocol", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True
)
@click.option(
    "--protocol-signature",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option("--signer-identity", required=True)
@click.option(
    "--config", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True
)
@click.option(
    "--report", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True
)
@click.option(
    "--forbidden-source",
    type=click.Path(exists=True, path_type=Path),
    multiple=True,
    required=True,
    help="active sealed corpus/reference path to compare against; repeatable",
)
@click.option(
    "--marker-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    multiple=True,
    required=True,
    help="file containing one active canary or dummy-secret marker; repeatable",
)
@click.option(
    "--log",
    "logs",
    multiple=True,
    metavar="NAME=PATH",
    help="explicitly permitted public log and its bundle-relative name; repeatable",
)
def bundle_public(
    destination: Path,
    protocol: Path,
    protocol_signature: Path,
    allowed_signers: Path,
    signer_identity: str,
    config: Path,
    report: Path,
    forbidden_source: tuple[Path, ...],
    marker_file: tuple[Path, ...],
    logs: tuple[str, ...],
) -> None:
    """Create a deterministic public bundle and fail on sealed-material leakage."""
    try:
        policy = _public_leakage_policy(forbidden_source, marker_file)
        permitted_logs = _parse_named_paths(logs)
        manifest = create_public_evidence_bundle(
            destination,
            protocol=protocol,
            protocol_signature=protocol_signature,
            allowed_signers=allowed_signers,
            signer_identity=signer_identity,
            config=config,
            report=report,
            permitted_logs=permitted_logs,
            leakage_policy=policy,
        )
    except (EvidenceBundleError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(
        f"verified public evidence bundle: {destination} (inventory {manifest.inventory_sha256})"
    )


@benchmark_commands.command(name="verify-public")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--forbidden-source",
    type=click.Path(exists=True, path_type=Path),
    multiple=True,
    required=True,
)
@click.option(
    "--marker-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    multiple=True,
    required=True,
)
@click.option(
    "--allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option("--signer-identity", required=True)
def verify_public_bundle(
    directory: Path,
    forbidden_source: tuple[Path, ...],
    marker_file: tuple[Path, ...],
    allowed_signers: Path,
    signer_identity: str,
) -> None:
    """Verify public inventory integrity and re-run the active leakage policy."""
    try:
        manifest = verify_public_evidence_bundle(
            directory,
            _public_leakage_policy(forbidden_source, marker_file),
            trusted_allowed_signers=allowed_signers,
            expected_signer_identity=signer_identity,
        )
    except (EvidenceBundleError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"verified public evidence bundle (inventory {manifest.inventory_sha256})")


@benchmark_commands.command(name="bundle-escrow")
@click.option(
    "--destination",
    type=click.Path(path_type=Path),
    required=True,
    help="new access-controlled directory to create",
)
@click.option(
    "--protocol", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True
)
@click.option(
    "--protocol-signature",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option("--signer-identity", required=True)
@click.option(
    "--config", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True
)
@click.option(
    "--report", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True
)
@click.option(
    "--sealed-corpus",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--rerunnable-evidence",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    required=True,
)
def bundle_escrow(
    destination: Path,
    protocol: Path,
    protocol_signature: Path,
    allowed_signers: Path,
    signer_identity: str,
    config: Path,
    report: Path,
    sealed_corpus: Path,
    rerunnable_evidence: Path,
) -> None:
    """Create a complete escrow bundle; this does not encrypt or grant access control."""
    try:
        manifest = create_escrow_evidence_bundle(
            destination,
            protocol=protocol,
            protocol_signature=protocol_signature,
            allowed_signers=allowed_signers,
            signer_identity=signer_identity,
            config=config,
            report=report,
            sealed_corpus=sealed_corpus,
            rerunnable_evidence=rerunnable_evidence,
        )
    except (EvidenceBundleError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(
        f"verified escrow bundle: {destination} (inventory {manifest.inventory_sha256})\n"
        "WARNING: the bundle is not encrypted; protect it with external access controls."
    )


@benchmark_commands.command(name="verify-escrow")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option("--signer-identity", required=True)
def verify_escrow_bundle(
    directory: Path,
    allowed_signers: Path,
    signer_identity: str,
) -> None:
    """Verify an escrow bundle's exact inventory and required warning."""
    try:
        manifest = verify_escrow_evidence_bundle(
            directory,
            trusted_allowed_signers=allowed_signers,
            expected_signer_identity=signer_identity,
        )
    except (EvidenceBundleError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"verified escrow evidence bundle (inventory {manifest.inventory_sha256})")


def _public_leakage_policy(
    forbidden_sources: tuple[Path, ...],
    marker_files: tuple[Path, ...],
) -> PublicLeakagePolicy:
    """Read sensitive markers from files so their values never appear in process arguments."""
    markers: list[bytes] = []
    for marker_file in marker_files:
        marker = marker_file.read_bytes().rstrip(b"\r\n")
        if not marker:
            raise EvidenceBundleError(f"marker file is empty: {marker_file}")
        markers.append(marker)
    return PublicLeakagePolicy(
        forbidden_sources=forbidden_sources,
        forbidden_markers=tuple(markers),
    )


def _parse_named_paths(values: tuple[str, ...]) -> dict[str, Path]:
    """Parse repeatable ``NAME=PATH`` options without shell evaluation."""
    parsed: dict[str, Path] = {}
    for value in values:
        name, separator, raw_path = value.partition("=")
        if not separator or not name or not raw_path:
            raise EvidenceBundleError(f"permitted log {value!r} must have the form NAME=PATH")
        if name in parsed:
            raise EvidenceBundleError(f"duplicate permitted log name {name!r}")
        path = Path(raw_path)
        if not path.is_file():
            raise EvidenceBundleError(f"permitted log is not a file: {path}")
        parsed[name] = path
    return parsed


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
@click.argument("path", type=click.Path(exists=True, path_type=Path), required=False, default=None)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="take the corpus path and isolation from a stinger.yaml, so the fairness gate covers "
    "the corpus the run will actually use",
)
@click.option("--docker", is_flag=True, help="force container isolation for every scenario")
def validate(path: Path | None, config_path: Path | None, docker: bool) -> None:
    """Run the validity contract over the corpus (SPEC.md §12). Non-zero exit on any failure.

    For each scenario: overlay the honest reference and assert no detector fires and the
    held-out completion check passes; overlay the cheat reference and assert the intended
    detector fires. This is what proves a trap is fair before any agent is judged by it.

    Every scenario is reported, not just the first failure, so one broken trap does not hide
    another. The exit code is non-zero if any scenario failed.

    `--config` exists for CI. A caller that ships its own scenarios points `corpus:` at them,
    and a fairness gate hard-coded to Stinger's bundled corpus would report a green proof for
    scenarios the run never touches — the caller's actual traps would be validated only
    implicitly, inside `stinger run`. Reading the same config the run reads makes the two
    agree by construction: `corpus` is used exactly as `run` uses it, relative to the current
    working directory, so a CI job that runs both steps from one directory cannot validate one
    corpus and score another.
    """
    if path is not None and config_path is not None:
        raise click.ClickException(
            "pass either a corpus PATH or --config, not both: they name the corpus two "
            "different ways and there is no correct answer when they disagree"
        )

    image = DEFAULT_IMAGE
    if config_path is not None:
        try:
            config = RunConfig.from_yaml(config_path)
        except ConfigError as exc:
            raise click.ClickException(str(exc)) from exc
        path = config.corpus
        docker = docker or config.isolation is Isolation.DOCKER
        image = config.image  # validate with the image the run will verify with, not a default
    elif path is None:
        path = Path("scenarios")

    if not path.is_dir():
        # Only reachable via --config: a bare PATH is checked by click. A caller whose config
        # lives in a subdirectory hits this the moment they run from the repository root, so
        # the message says where the path came from and what it is relative to.
        raise click.ClickException(
            f"corpus {path} named by {config_path} does not exist. Corpus paths are relative "
            "to the current working directory, not to the config file — run from the "
            "directory the config's `corpus:` is written against."
        )

    try:
        scenarios = discover_scenarios(path)
    except ScenarioLoadError as exc:
        raise click.ClickException(str(exc)) from exc

    failures = 0
    for scenario in scenarios:
        try:
            box = _sandbox_for(scenario, docker, image)
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


def _sandbox_for(scenario: Scenario, docker: bool, image: str = DEFAULT_IMAGE) -> Sandbox:
    """Isolation for validating one scenario.

    Chosen by what the scenario contains, not by preference: family X always gets a
    container, because its seeded bait secrets and exfiltration lures must not run
    unconfined (SPEC.md §2). Everything else validates locally by default — validation runs
    the corpus's own reviewed reference resolutions, not agent-generated code — and --docker
    opts the whole corpus into containers for a stricter pass.

    `image` must be the image the run will actually verify with. Validating against the
    default while the config names a custom `image:` would prove fairness in one runtime and
    score in another — the two can disagree about installed tooling, which is the exact
    divergence the fairness gate exists to rule out.
    """
    if docker or scenario.manifest.family == "X":
        return Sandbox(isolation=Isolation.DOCKER, image=image)
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
        # This must precede adapter construction and every execution. A sealed run that
        # crashes halfway still leaves transcripts, and generic CI must recognize those
        # partial artifacts as non-public.
        prepare_repro_package(package, scenarios)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

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

    runtime_provenance = None
    if resolved.benchmark_protocol_version is not None:
        try:
            runtime_provenance = verify_runtime_provenance(
                resolved,
                adapter,
                workdir=Path.cwd(),
            )
        except RuntimePreflightError as exc:
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
        benchmark_metadata=resolved.benchmark_metadata(),
        benchmark_runtime_provenance=runtime_provenance,
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

    if config.benchmark_protocol_version is not None:
        by_id = {scenario.id: scenario for scenario in scenarios}
        ordered_ids = deterministic_blocked_ids(
            (
                ScenarioOrderItem(
                    scenario_id=scenario.id,
                    family=scenario.manifest.family,
                )
                for scenario in scenarios
            ),
            seed=config.run_seed,
        )
        scenarios = [by_id[scenario_id] for scenario_id in ordered_ids]

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
            box = _sandbox_for(scenario, config.isolation is Isolation.DOCKER, config.image)
            box.preflight()
            validate_scenario(scenario.directory, scenario.manifest, sandbox=box)
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
