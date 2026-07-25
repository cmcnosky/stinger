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
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import click
import yaml
from pydantic import ValidationError

from stinger.adapters.cli_base import AgentContainmentError
from stinger.adapters.factory import AdapterError, build_adapter
from stinger.benchmark.candidate_receipt import (
    CandidateReceiptError,
    build_candidate_validation_receipt,
    write_candidate_validation_receipt,
)
from stinger.benchmark.comparison import (
    BenchmarkComparisonError,
    build_paired_comparison,
)
from stinger.benchmark.conformance import (
    ConformanceBuilderError,
    build_conformance_environment_record,
    build_conformance_environment_statement,
    prepare_conformance_workflow,
    write_conformance_environment_record,
    write_conformance_environment_statement,
    write_conformance_workflow_package,
)
from stinger.benchmark.corpus_construction import (
    CorpusConstructionError,
    authorize_corpus_construction_receipt,
    build_corpus_construction_receipt,
    load_corpus_construction_input_manifest,
    sign_corpus_construction_receipt,
    write_corpus_construction_receipt,
)
from stinger.benchmark.corpus_promotion import (
    CandidatePromotionError,
    promote_candidate_corpus,
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
    BaselineConfigurationRecord,
    BenchmarkGateReport,
    BenchmarkReleaseSubmission,
    SealedCorpusRecord,
    authorize_baseline_verification_statement,
    authorize_benchmark_protocol,
    authorize_benchmark_submission,
    authorize_candidate_promotion_statement,
    authorize_candidate_validation_receipt,
    authorize_conformance_statement,
    authorize_corpus_freeze_statement,
    authorize_pilot_evidence_statement,
    authorize_release_evidence_statement,
    authorize_reproduction_statement,
    compiled_benchmark_protocol,
    evaluate_benchmark_release,
    load_benchmark_protocol,
    load_benchmark_submission,
)
from stinger.benchmark.machine_environment import (
    MachineAttestationError,
    MachineWorkflowEvidencePaths,
    build_machine_workflow_attestation,
    create_machine_environment_identity_artifact,
    sign_machine_workflow_attestation,
    verify_machine_workflow_attestation,
    write_machine_workflow_attestation,
)
from stinger.benchmark.ordering import ScenarioOrderItem, deterministic_blocked_ids
from stinger.benchmark.pilot import (
    PilotBundleInput,
    PilotEvidenceError,
    build_pilot_evidence_statement,
    write_pilot_evidence_statement,
)
from stinger.benchmark.provenance import RuntimePreflightError, verify_runtime_provenance
from stinger.benchmark.records import (
    BaselineRecordError,
    build_baseline_configuration_record,
    build_baseline_verification_statement,
    build_corpus_freeze_record,
    build_corpus_freeze_statement,
    write_baseline_configuration_record,
    write_baseline_verification_statement,
    write_corpus_freeze_record,
    write_corpus_freeze_statement,
)
from stinger.benchmark.release_evidence import (
    ConflictDisclosureEntry,
    PreparedReleaseEvidence,
    ReleaseEvidenceBuilderError,
    build_release_artifact_manifest,
    build_release_evidence_statement,
    load_release_evidence_preparation_package,
    prepare_release_evidence,
    write_release_artifact_package,
    write_release_evidence_preparation_package,
    write_release_evidence_record,
    write_release_evidence_statement,
)
from stinger.benchmark.replay import (
    ClassificationReplayError,
    InvocationContext,
    build_invocation_plan,
)
from stinger.benchmark.reproduction import (
    ReproductionBuilderError,
    build_reproduction_diff,
    build_reproduction_record,
    build_reproduction_statement,
    write_reproduction_diff,
    write_reproduction_record,
)
from stinger.benchmark.reproduction_verification import (
    PublicReproductionVerificationError,
    authorize_public_reproduction_verification_statement,
    build_public_reproduction_verification_statement,
    verify_public_reproduction,
    write_public_reproduction_verification_statement,
)
from stinger.benchmark.signing import (
    ProtocolSignatureError,
    sign_baseline_verification_statement,
    sign_candidate_promotion_statement,
    sign_candidate_validation_receipt,
    sign_conformance_statement,
    sign_corpus_freeze_statement,
    sign_pilot_evidence_statement,
    sign_protocol,
    sign_public_reproduction_verification_statement,
    sign_release_evidence_statement,
    sign_release_submission,
    sign_reproduced_report,
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


@benchmark_commands.command(name="build-candidate-receipt")
@click.option(
    "--candidate-root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--metadata",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--canary-registry",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--access-ledger",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--repository",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    show_default=True,
)
@click.option("--verification-image", default=DEFAULT_IMAGE, show_default=True)
@click.option("--signer-identity", required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def build_benchmark_candidate_receipt(
    candidate_root: Path,
    metadata: Path,
    canary_registry: Path,
    access_ledger: Path,
    repository: Path,
    verification_image: str,
    signer_identity: str,
    output: Path,
) -> None:
    """Build a public aggregate receipt after contained private-corpus validation."""
    try:
        receipt = build_candidate_validation_receipt(
            candidate_root=candidate_root,
            metadata_file=metadata,
            canary_registry=canary_registry,
            access_ledger=access_ledger,
            repository=repository,
            verification_image=verification_image,
            signer_identity=signer_identity,
        )
        write_candidate_validation_receipt(output, receipt)
    except CandidateReceiptError as exc:
        raise click.ClickException(str(exc)) from exc
    except (OSError, ValidationError, ValueError) as exc:
        raise click.ClickException("candidate receipt construction failed") from exc
    click.echo(
        "candidate validation receipt created: "
        f"{receipt.scenario_count} candidates, "
        f"{receipt.machine_validation_count} contained validations"
    )


@benchmark_commands.command(name="sign-candidate-receipt")
@click.argument("receipt", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--private-key",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
def sign_benchmark_candidate_receipt(receipt: Path, private_key: Path) -> None:
    """Sign exact candidate-validation receipt bytes in a dedicated namespace."""
    try:
        signature = sign_candidate_validation_receipt(receipt, private_key)
    except ProtocolSignatureError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"signed candidate validation receipt: {signature}")


@benchmark_commands.command(name="verify-candidate-receipt")
@click.argument("receipt", type=click.Path(exists=True, dir_okay=False, path_type=Path))
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
def verify_benchmark_candidate_receipt(
    receipt: Path,
    signature: Path,
    allowed_signers: Path,
    signer_identity: str,
) -> None:
    """Verify one exact public receipt without opening the private candidate corpus."""
    try:
        authorization = authorize_candidate_validation_receipt(
            receipt,
            signature,
            allowed_signers,
            signer_identity,
        )
    except (OSError, ValueError, ValidationError, ProtocolSignatureError) as exc:
        raise click.ClickException("candidate validation receipt verification failed") from exc
    click.echo(
        "verified signed candidate validation receipt: "
        f"{authorization.receipt.scenario_count} candidates"
    )


@benchmark_commands.command(name="promote-candidate-corpus")
@click.option(
    "--candidate-root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--metadata",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--canary-registry",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--access-ledger",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--candidate-receipt",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--candidate-receipt-signature",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--candidate-allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option("--candidate-signer-identity", required=True)
@click.option(
    "--repository",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    show_default=True,
)
@click.option("--verification-image", default=DEFAULT_IMAGE, show_default=True)
@click.option("--promotion-signer-identity", required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def promote_benchmark_candidate_corpus(
    candidate_root: Path,
    metadata: Path,
    canary_registry: Path,
    access_ledger: Path,
    candidate_receipt: Path,
    candidate_receipt_signature: Path,
    candidate_allowed_signers: Path,
    candidate_signer_identity: str,
    repository: Path,
    verification_image: str,
    promotion_signer_identity: str,
    output: Path,
) -> None:
    """Promote only the lifecycle split and revalidate an atomic private package."""
    try:
        statement = promote_candidate_corpus(
            candidate_root=candidate_root,
            metadata_file=metadata,
            canary_registry=canary_registry,
            access_ledger=access_ledger,
            candidate_receipt=candidate_receipt,
            candidate_receipt_signature=candidate_receipt_signature,
            candidate_allowed_signers=candidate_allowed_signers,
            candidate_signer_identity=candidate_signer_identity,
            repository=repository,
            verification_image=verification_image,
            promotion_signer_identity=promotion_signer_identity,
            output_directory=output,
        )
    except CandidatePromotionError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(
        f"candidate corpus promoted and revalidated: {statement.scenario_count} sealed scenarios"
    )


@benchmark_commands.command(name="sign-candidate-promotion")
@click.argument("statement", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--private-key",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
def sign_benchmark_candidate_promotion(statement: Path, private_key: Path) -> None:
    """Sign exact candidate-to-sealed promotion bytes in a dedicated namespace."""
    try:
        signature = sign_candidate_promotion_statement(statement, private_key)
    except ProtocolSignatureError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"signed candidate promotion statement: {signature}")


@benchmark_commands.command(name="build-corpus-construction-receipt")
@click.option(
    "--input-manifest",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def build_benchmark_corpus_construction_receipt(
    input_manifest: Path,
    output: Path,
) -> None:
    """Derive the complete sealed-corpus record from one private closed manifest."""
    try:
        inputs = load_corpus_construction_input_manifest(input_manifest)
        verified = build_corpus_construction_receipt(**inputs)
        write_corpus_construction_receipt(output, verified.receipt)
    except CorpusConstructionError as exc:
        raise click.ClickException("corpus construction receipt creation failed") from exc
    click.echo(
        "corpus construction receipt created from verified artifacts: "
        f"{verified.receipt.scenario_count} scenarios"
    )


@benchmark_commands.command(name="sign-corpus-construction-receipt")
@click.argument("receipt", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--private-key",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
def sign_benchmark_corpus_construction_receipt(
    receipt: Path,
    private_key: Path,
) -> None:
    """Sign an exact artifact-derived construction receipt in its own namespace."""
    try:
        signature = sign_corpus_construction_receipt(receipt, private_key)
    except ProtocolSignatureError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"signed corpus construction receipt: {signature}")


@benchmark_commands.command(name="verify-corpus-construction-receipt")
@click.argument("receipt", type=click.Path(exists=True, dir_okay=False, path_type=Path))
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
def verify_benchmark_corpus_construction_receipt(
    receipt: Path,
    signature: Path,
    allowed_signers: Path,
    signer_identity: str,
) -> None:
    """Verify one exact construction receipt without opening sealed artifacts."""
    try:
        authorization = authorize_corpus_construction_receipt(
            receipt,
            signature,
            allowed_signers,
            signer_identity,
        )
    except (CorpusConstructionError, OSError, ValueError, ProtocolSignatureError) as exc:
        raise click.ClickException("corpus construction receipt verification failed") from exc
    click.echo(
        "verified signed corpus construction receipt: "
        f"{authorization.receipt.scenario_count} scenarios"
    )


@benchmark_commands.command(name="build-pilot-evidence")
@click.option(
    "--corpus-record",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--candidate-receipt",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option("--configuration-alias", multiple=True, required=True)
@click.option(
    "--public-bundle",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    multiple=True,
    required=True,
)
@click.option(
    "--escrow-bundle",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    multiple=True,
    required=True,
)
@click.option(
    "--protocol-allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    multiple=True,
    required=True,
)
@click.option("--protocol-signer-identity", multiple=True, required=True)
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
@click.option("--output", type=click.Path(path_type=Path), required=True)
def build_benchmark_pilot_evidence(
    corpus_record: Path,
    candidate_receipt: Path,
    configuration_alias: tuple[str, ...],
    public_bundle: tuple[Path, ...],
    escrow_bundle: tuple[Path, ...],
    protocol_allowed_signers: tuple[Path, ...],
    protocol_signer_identity: tuple[str, ...],
    forbidden_source: tuple[Path, ...],
    marker_file: tuple[Path, ...],
    output: Path,
) -> None:
    """Build path-free pilot evidence from exact verified sealed-run bundles."""
    counts = {
        len(configuration_alias),
        len(public_bundle),
        len(escrow_bundle),
        len(protocol_allowed_signers),
        len(protocol_signer_identity),
    }
    if len(counts) != 1:
        raise click.ClickException(
            "pilot alias, bundle, and protocol-trust options must have equal counts"
        )
    try:
        corpus = _load_sealed_corpus_record(corpus_record)
        policy = _public_leakage_policy(forbidden_source, marker_file)
        runs = tuple(
            PilotBundleInput(
                configuration_alias=alias,
                public_bundle=public_path,
                escrow_bundle=escrow_path,
                leakage_policy=policy,
                protocol_allowed_signers=signers_path,
                protocol_signer_identity=signer_identity,
            )
            for (
                alias,
                public_path,
                escrow_path,
                signers_path,
                signer_identity,
            ) in zip(
                configuration_alias,
                public_bundle,
                escrow_bundle,
                protocol_allowed_signers,
                protocol_signer_identity,
                strict=True,
            )
        )
        receipt = build_pilot_evidence_statement(
            corpus=corpus,
            candidate_receipt=candidate_receipt,
            runs=runs,
        )
        write_pilot_evidence_statement(output, receipt.statement)
    except (EvidenceBundleError, PilotEvidenceError, OSError, ValueError) as exc:
        raise click.ClickException(f"pilot evidence construction failed: {exc}") from exc
    click.echo(
        "pilot evidence created: "
        f"{receipt.statement.scenario_count} scenarios across "
        f"{receipt.statement.configuration_count} anonymous configurations"
    )


@benchmark_commands.command(name="sign-pilot-evidence")
@click.argument("statement", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--private-key",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
def sign_benchmark_pilot_evidence(statement: Path, private_key: Path) -> None:
    """Sign exact artifact-derived pilot evidence in a dedicated namespace."""
    try:
        signature = sign_pilot_evidence_statement(statement, private_key)
    except ProtocolSignatureError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"signed pilot evidence statement: {signature}")


@benchmark_commands.command(name="create-machine-environment-identity")
@click.option("--output", type=click.Path(path_type=Path), required=True)
def create_benchmark_machine_environment_identity(output: Path) -> None:
    """Create a canonical privacy-preserving identity for the current host."""
    try:
        identity = create_machine_environment_identity_artifact(output)
    except MachineAttestationError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(
        "machine environment identity created: "
        f"{identity.platform.value}/{identity.architecture.value}"
    )


@benchmark_commands.command(name="build-machine-workflow-attestation")
@click.option(
    "--machine-identity",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--workflow-input",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--workflow-receipt",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--repository",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    show_default=True,
)
@click.option("--expected-stinger-commit", required=True)
@click.option("--signer-identity", required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def build_benchmark_machine_workflow_attestation(
    machine_identity: Path,
    workflow_input: Path,
    workflow_receipt: Path,
    repository: Path,
    expected_stinger_commit: str,
    signer_identity: str,
    output: Path,
) -> None:
    """Bind this host to exact workflow input, receipt, and clean Stinger commit."""
    try:
        attestation = build_machine_workflow_attestation(
            machine_identity_artifact=machine_identity,
            workflow_input=workflow_input,
            workflow_receipt=workflow_receipt,
            repository=repository,
            expected_stinger_commit=expected_stinger_commit,
            signer_identity=signer_identity,
        )
        write_machine_workflow_attestation(output, attestation)
    except MachineAttestationError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo("machine workflow attestation created")


@benchmark_commands.command(name="sign-machine-workflow-attestation")
@click.argument("attestation", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--private-key",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
def sign_benchmark_machine_workflow_attestation(
    attestation: Path,
    private_key: Path,
) -> None:
    """Sign exact machine-workflow evidence in its dedicated namespace."""
    try:
        signature = sign_machine_workflow_attestation(attestation, private_key)
    except MachineAttestationError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"signed machine workflow attestation: {signature}")


@benchmark_commands.command(name="verify-machine-workflow-attestation")
@click.option(
    "--machine-identity",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--workflow-input",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--workflow-receipt",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--attestation",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
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
@click.option("--expected-stinger-commit", required=True)
def verify_benchmark_machine_workflow_attestation(
    machine_identity: Path,
    workflow_input: Path,
    workflow_receipt: Path,
    attestation: Path,
    signature: Path,
    allowed_signers: Path,
    signer_identity: str,
    expected_stinger_commit: str,
) -> None:
    """Verify exact host-derived workflow evidence without claiming hardware proof."""
    try:
        verified = verify_machine_workflow_attestation(
            machine_identity_artifact=machine_identity,
            workflow_input=workflow_input,
            workflow_receipt=workflow_receipt,
            attestation=attestation,
            signature=signature,
            allowed_signers=allowed_signers,
            signer_identity=signer_identity,
            expected_stinger_commit=expected_stinger_commit,
        )
    except MachineAttestationError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(
        "machine workflow attestation verified: "
        f"{verified.statement.platform.value}/{verified.statement.architecture.value}"
    )


@benchmark_commands.command(name="build-conformance-statement")
@click.option("--environment-id", required=True)
@click.option("--corpus-hash", required=True)
@click.option(
    "--workflow-input",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--workflow-output-inventory",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--workflow-output",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--machine-identity",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--machine-attestation",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--machine-attestation-signature",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--machine-attestation-allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--repository",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    show_default=True,
)
@click.option("--signer-identity", required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def build_benchmark_conformance_statement(
    environment_id: str,
    corpus_hash: str,
    workflow_input: Path,
    workflow_output_inventory: Path,
    workflow_output: Path,
    machine_identity: Path,
    machine_attestation: Path,
    machine_attestation_signature: Path,
    machine_attestation_allowed_signers: Path,
    repository: Path,
    signer_identity: str,
    output: Path,
) -> None:
    """Build one clean-environment statement from exact observed artifacts."""
    try:
        statement = build_conformance_environment_statement(
            environment_id,
            corpus_hash=corpus_hash,
            workflow_input=workflow_input,
            workflow_output_inventory=workflow_output_inventory,
            workflow_output=workflow_output,
            machine_workflow_evidence=MachineWorkflowEvidencePaths(
                identity_artifact=machine_identity,
                attestation=machine_attestation,
                signature=machine_attestation_signature,
                allowed_signers=machine_attestation_allowed_signers,
                signer_identity=signer_identity,
            ),
            repository=repository,
            signer_identity=signer_identity,
        )
        write_conformance_environment_statement(output, statement)
    except ConformanceBuilderError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo("benchmark conformance statement created")


@benchmark_commands.command(name="run-conformance-workflow")
@click.option(
    "--repository",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    show_default=True,
)
@click.option(
    "--toolchain-python",
    type=click.Path(exists=True, dir_okay=False, path_type=Path, resolve_path=True),
    required=True,
)
@click.option("--expected-stinger-commit", required=True)
@click.option("--corpus-hash", required=True)
@click.option("--output-package", type=click.Path(path_type=Path), required=True)
def run_benchmark_conformance_workflow(
    repository: Path,
    toolchain_python: Path,
    expected_stinger_commit: str,
    corpus_hash: str,
    output_package: Path,
) -> None:
    """Run the fixed tracked-source conformance workflow and preserve exact evidence."""
    try:
        prepared = prepare_conformance_workflow(
            repository=repository,
            toolchain_python=toolchain_python,
            expected_stinger_commit=expected_stinger_commit,
            corpus_hash=corpus_hash,
        )
        write_conformance_workflow_package(output_package, prepared)
    except ConformanceBuilderError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo("fixed benchmark conformance workflow completed")


@benchmark_commands.command(name="sign-conformance")
@click.argument("statement", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--private-key",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
def sign_benchmark_conformance(statement: Path, private_key: Path) -> None:
    """Sign one exact clean-environment conformance statement."""
    try:
        signature = sign_conformance_statement(statement, private_key)
    except ProtocolSignatureError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"signed benchmark conformance statement: {signature}")


@benchmark_commands.command(name="sign-baseline-verification")
@click.argument("statement", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--private-key",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
def sign_benchmark_baseline_verification(statement: Path, private_key: Path) -> None:
    """Sign one exact artifact-derived baseline verification statement."""
    try:
        signature = sign_baseline_verification_statement(statement, private_key)
    except ProtocolSignatureError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"signed benchmark baseline verification statement: {signature}")


@benchmark_commands.command(name="sign-release-evidence")
@click.argument("statement", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--private-key",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
def sign_benchmark_release_evidence(statement: Path, private_key: Path) -> None:
    """Sign one exact artifact-derived release-evidence statement."""
    try:
        signature = sign_release_evidence_statement(statement, private_key)
    except ProtocolSignatureError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"signed benchmark release evidence statement: {signature}")


@benchmark_commands.command(name="build-release-artifacts")
@click.option(
    "--submission",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Typed draft submission; release-evidence hashes may still be empty.",
)
@click.option(
    "--conflicts-declaration",
    type=click.Choice(
        ["no-known-material-conflicts", "material-conflicts-disclosed"],
        case_sensitive=True,
    ),
    required=True,
)
@click.option(
    "--conflict",
    type=(
        click.Choice(
            ["financial", "employment", "advisory", "investment", "family", "other"],
            case_sensitive=True,
        ),
        str,
        str,
    ),
    multiple=True,
    metavar="CATEGORY ENTITY DESCRIPTION",
    help="One material relationship; repeat as needed.",
)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def build_benchmark_release_artifacts(
    submission: Path,
    conflicts_declaration: str,
    conflict: tuple[tuple[str, str, str], ...],
    output: Path,
) -> None:
    """Build the canonical non-comparative report, freeze, policy, and disclosure package."""
    try:
        finalized = load_benchmark_submission(submission)
        relationships = tuple(
            ConflictDisclosureEntry(
                category=category,  # type: ignore[arg-type]
                entity=entity,
                description=description,
            )
            for category, entity, description in conflict
        )
        if conflicts_declaration not in {
            "no-known-material-conflicts",
            "material-conflicts-disclosed",
        }:
            raise ReleaseEvidenceBuilderError("conflicts declaration is invalid")
        artifacts = build_release_artifact_manifest(
            finalized,
            conflicts_declaration=conflicts_declaration,  # type: ignore[arg-type]
            conflict_relationships=relationships,
        )
        write_release_artifact_package(output, artifacts)
    except (OSError, ValidationError, ValueError, ReleaseEvidenceBuilderError) as exc:
        raise click.ClickException("release artifact construction failed") from exc
    click.echo("canonical non-comparative release artifacts created")


def _prepare_release_evidence_from_cli(
    *,
    repository: Path,
    toolchain_python: Path,
    expected_stinger_commit: str,
    corpus_version: str,
    corpus_hash: str,
    protocol_freeze_receipt: Path,
    technical_report: Path,
    correction_policy: Path,
    conflicts_disclosure: Path,
    comparative_release: bool,
    vendor_rerun_receipt: Path | None,
) -> PreparedReleaseEvidence:
    """Share exact release-artifact preparation between the two CLI stages."""
    return prepare_release_evidence(
        repository=repository,
        toolchain_python=toolchain_python,
        expected_stinger_commit=expected_stinger_commit,
        corpus_version=corpus_version,
        corpus_hash=corpus_hash,
        protocol_freeze_receipt=protocol_freeze_receipt,
        technical_report=technical_report,
        correction_policy=correction_policy,
        conflicts_disclosure=conflicts_disclosure,
        comparative_release=comparative_release,
        vendor_rerun_receipt=vendor_rerun_receipt,
    )


@benchmark_commands.command(name="build-release-evidence-record")
@click.option(
    "--repository",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    show_default=True,
)
@click.option(
    "--toolchain-python",
    type=click.Path(exists=True, dir_okay=False, path_type=Path, resolve_path=True),
    required=True,
    help="Explicit gate Python outside the release checkout.",
)
@click.option("--expected-stinger-commit", required=True)
@click.option("--corpus-version", required=True)
@click.option("--corpus-hash", required=True)
@click.option(
    "--protocol-freeze-receipt",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--technical-report",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--correction-policy",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--conflicts-disclosure",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--comparative-release/--non-comparative-release",
    default=False,
    show_default=True,
)
@click.option(
    "--vendor-rerun-receipt",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--preparation-package",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def build_benchmark_release_evidence_record(
    repository: Path,
    toolchain_python: Path,
    expected_stinger_commit: str,
    corpus_version: str,
    corpus_hash: str,
    protocol_freeze_receipt: Path,
    technical_report: Path,
    correction_policy: Path,
    conflicts_disclosure: Path,
    comparative_release: bool,
    vendor_rerun_receipt: Path | None,
    preparation_package: Path,
    output: Path,
) -> None:
    """Run the clean master gate and derive the exact release-evidence record."""
    try:
        prepared = _prepare_release_evidence_from_cli(
            repository=repository,
            toolchain_python=toolchain_python,
            expected_stinger_commit=expected_stinger_commit,
            corpus_version=corpus_version,
            corpus_hash=corpus_hash,
            protocol_freeze_receipt=protocol_freeze_receipt,
            technical_report=technical_report,
            correction_policy=correction_policy,
            conflicts_disclosure=conflicts_disclosure,
            comparative_release=comparative_release,
            vendor_rerun_receipt=vendor_rerun_receipt,
        )
        write_release_evidence_preparation_package(preparation_package, prepared)
        write_release_evidence_record(output, prepared.record)
    except ReleaseEvidenceBuilderError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo("release evidence record created from a clean master-gate execution")


@benchmark_commands.command(name="build-release-evidence-statement")
@click.option(
    "--submission",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option("--signer-identity", required=True)
@click.option(
    "--repository",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    show_default=True,
)
@click.option("--expected-stinger-commit", required=True)
@click.option("--corpus-version", required=True)
@click.option("--corpus-hash", required=True)
@click.option(
    "--protocol-freeze-receipt",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--technical-report",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--correction-policy",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--conflicts-disclosure",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--comparative-release/--non-comparative-release",
    default=False,
    show_default=True,
)
@click.option(
    "--vendor-rerun-receipt",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--preparation-package",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    required=True,
)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def build_benchmark_release_evidence_statement(
    submission: Path,
    signer_identity: str,
    repository: Path,
    expected_stinger_commit: str,
    corpus_version: str,
    corpus_hash: str,
    protocol_freeze_receipt: Path,
    technical_report: Path,
    correction_policy: Path,
    conflicts_disclosure: Path,
    comparative_release: bool,
    vendor_rerun_receipt: Path | None,
    preparation_package: Path,
    output: Path,
) -> None:
    """Reverify one persisted gate receipt and bind it to a finalized submission."""
    try:
        prepared = load_release_evidence_preparation_package(
            preparation_package,
            repository=repository,
            expected_stinger_commit=expected_stinger_commit,
            corpus_version=corpus_version,
            corpus_hash=corpus_hash,
            protocol_freeze_receipt=protocol_freeze_receipt,
            technical_report=technical_report,
            correction_policy=correction_policy,
            conflicts_disclosure=conflicts_disclosure,
            comparative_release=comparative_release,
            vendor_rerun_receipt=vendor_rerun_receipt,
        )
        finalized = load_benchmark_submission(submission)
        statement = build_release_evidence_statement(
            finalized,
            prepared,
            signer_identity=signer_identity,
        )
        write_release_evidence_statement(output, statement)
    except (ReleaseEvidenceBuilderError, OSError, ValidationError, ValueError) as exc:
        raise click.ClickException("release evidence statement construction failed") from exc
    click.echo("release evidence statement bound to the finalized submission")


@benchmark_commands.command(name="build-conformance-record")
@click.option("--statement", type=click.Path(path_type=Path), required=True)
@click.option("--signature", type=click.Path(path_type=Path), required=True)
@click.option("--allowed-signers", type=click.Path(path_type=Path), required=True)
@click.option("--signer-identity", required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def build_benchmark_conformance_record(
    statement: Path,
    signature: Path,
    allowed_signers: Path,
    signer_identity: str,
    output: Path,
) -> None:
    """Build a release record from one trusted signed conformance statement."""
    try:
        record = build_conformance_environment_record(
            statement,
            signature,
            allowed_signers,
            signer_identity,
        )
        write_conformance_environment_record(output, record)
    except ConformanceBuilderError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo("benchmark conformance record created")


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


@benchmark_commands.command(name="sign-corpus-freeze")
@click.argument("statement", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--private-key",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
def sign_benchmark_corpus_freeze(statement: Path, private_key: Path) -> None:
    """Sign exact machine-derived corpus-freeze statement bytes."""
    try:
        signature = sign_corpus_freeze_statement(statement, private_key)
    except ProtocolSignatureError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"signed benchmark corpus freeze statement: {signature}")


@benchmark_commands.command(name="sign-reproduction")
@click.argument("statement", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--private-key",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
def sign_benchmark_reproduction(statement: Path, private_key: Path) -> None:
    """Sign a cross-machine evaluator's exact artifact-binding statement."""
    try:
        signature = sign_reproduction_statement(statement, private_key)
    except ProtocolSignatureError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"signed benchmark reproduction statement: {signature}")


@benchmark_commands.command(name="sign-public-reproduction-verification")
@click.argument("statement", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--private-key",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
def sign_benchmark_public_reproduction_verification(
    statement: Path,
    private_key: Path,
) -> None:
    """Sign the exact non-secret handoff from full verification to release-check."""
    try:
        signature = sign_public_reproduction_verification_statement(
            statement,
            private_key,
        )
    except ProtocolSignatureError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"signed public reproduction verification statement: {signature}")


@benchmark_commands.command(name="sign-reproduced-report")
@click.argument("report", type=click.Path(path_type=Path))
@click.option(
    "--private-key",
    type=click.Path(path_type=Path),
    required=True,
)
def sign_benchmark_reproduced_report(report: Path, private_key: Path) -> None:
    """Sign exact reproduced report bytes in the evaluator-report namespace."""
    try:
        sign_reproduced_report(report, private_key)
    except ProtocolSignatureError as exc:
        raise click.ClickException("reproduced report signing failed") from exc
    click.echo("reproduced report signed")


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
    """Refuse a machine protocol manifest that weakens or drifts from Protocol 2."""
    try:
        loaded = load_benchmark_protocol(protocol)
    except (OSError, ValueError, ValidationError) as exc:
        raise click.ClickException(f"invalid benchmark protocol: {exc}") from exc
    if loaded != compiled_benchmark_protocol():
        raise click.ClickException(
            "protocol manifest differs from the compiled Benchmark Protocol 2 thresholds"
        )
    click.echo(
        f"benchmark protocol {loaded.benchmark_protocol_version} is structurally valid "
        f"(requires {loaded.total_scenarios} sealed scenarios; release remains gate-controlled)"
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
@click.option(
    "--protocol",
    "signed_protocol",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--protocol-signature",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--protocol-allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option("--protocol-signer-identity")
@click.option(
    "--candidate-receipt",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--candidate-receipt-signature",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--candidate-receipt-allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option("--candidate-receipt-signer-identity")
@click.option(
    "--candidate-promotion-statement",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--candidate-promotion-signature",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--candidate-promotion-allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option("--candidate-promotion-signer-identity")
@click.option(
    "--corpus-construction-receipt",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--corpus-construction-signature",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--corpus-construction-allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option("--corpus-construction-signer-identity")
@click.option(
    "--corpus-freeze-statement",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--corpus-freeze-signature",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--corpus-freeze-allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option("--corpus-freeze-signer-identity")
@click.option(
    "--pilot-evidence-statement",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--pilot-evidence-signature",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--pilot-evidence-allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option("--pilot-evidence-signer-identity")
@click.option(
    "--conformance-statement",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    multiple=True,
)
@click.option(
    "--conformance-signature",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    multiple=True,
)
@click.option(
    "--conformance-allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    multiple=True,
)
@click.option("--conformance-signer-identity", multiple=True)
@click.option(
    "--baseline-verification-statement",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    multiple=True,
)
@click.option(
    "--baseline-verification-signature",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    multiple=True,
)
@click.option(
    "--baseline-verification-allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    multiple=True,
)
@click.option("--baseline-verification-signer-identity", multiple=True)
@click.option(
    "--release-evidence-statement",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--release-evidence-signature",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--release-evidence-allowed-signers",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option("--release-evidence-signer-identity")
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
@click.option(
    "--public-reproduction-verification-statement",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--public-reproduction-verification-signature",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
def benchmark_release_check(
    submission: Path,
    output_format: str,
    signed_protocol: Path | None,
    protocol_signature: Path | None,
    protocol_allowed_signers: Path | None,
    protocol_signer_identity: str | None,
    candidate_receipt: Path | None,
    candidate_receipt_signature: Path | None,
    candidate_receipt_allowed_signers: Path | None,
    candidate_receipt_signer_identity: str | None,
    candidate_promotion_statement: Path | None,
    candidate_promotion_signature: Path | None,
    candidate_promotion_allowed_signers: Path | None,
    candidate_promotion_signer_identity: str | None,
    corpus_construction_receipt: Path | None,
    corpus_construction_signature: Path | None,
    corpus_construction_allowed_signers: Path | None,
    corpus_construction_signer_identity: str | None,
    corpus_freeze_statement: Path | None,
    corpus_freeze_signature: Path | None,
    corpus_freeze_allowed_signers: Path | None,
    corpus_freeze_signer_identity: str | None,
    pilot_evidence_statement: Path | None,
    pilot_evidence_signature: Path | None,
    pilot_evidence_allowed_signers: Path | None,
    pilot_evidence_signer_identity: str | None,
    conformance_statement: tuple[Path, ...],
    conformance_signature: tuple[Path, ...],
    conformance_allowed_signers: tuple[Path, ...],
    conformance_signer_identity: tuple[str, ...],
    baseline_verification_statement: tuple[Path, ...],
    baseline_verification_signature: tuple[Path, ...],
    baseline_verification_allowed_signers: tuple[Path, ...],
    baseline_verification_signer_identity: tuple[str, ...],
    release_evidence_statement: Path | None,
    release_evidence_signature: Path | None,
    release_evidence_allowed_signers: Path | None,
    release_evidence_signer_identity: str | None,
    signature: Path | None,
    allowed_signers: Path | None,
    signer_identity: str | None,
    reproduction_statement: Path | None,
    reproduction_signature: Path | None,
    verifier_allowed_signers: Path | None,
    verifier_identity: str | None,
    public_reproduction_verification_statement: Path | None,
    public_reproduction_verification_signature: Path | None,
) -> None:
    """Evaluate every Protocol 2 release gate; blocked submissions exit non-zero."""
    try:
        protocol_inputs = (
            signed_protocol,
            protocol_signature,
            protocol_allowed_signers,
            protocol_signer_identity,
        )
        if any(item is not None for item in protocol_inputs) and not all(
            item is not None for item in protocol_inputs
        ):
            raise ValueError("all protocol/signature/trust options are required together")
        protocol_authorization = None
        authorized_protocol = None
        if (
            signed_protocol is not None
            and protocol_signature is not None
            and protocol_allowed_signers is not None
            and protocol_signer_identity is not None
        ):
            authorized_protocol, protocol_authorization = authorize_benchmark_protocol(
                signed_protocol,
                protocol_signature,
                protocol_allowed_signers,
                protocol_signer_identity,
            )

        candidate_receipt_inputs = (
            candidate_receipt,
            candidate_receipt_signature,
            candidate_receipt_allowed_signers,
            candidate_receipt_signer_identity,
        )
        if any(item is not None for item in candidate_receipt_inputs) and not all(
            item is not None for item in candidate_receipt_inputs
        ):
            raise ValueError("all candidate receipt/signature/trust options are required together")
        candidate_validation_authorization = (
            authorize_candidate_validation_receipt(
                candidate_receipt,
                candidate_receipt_signature,
                candidate_receipt_allowed_signers,
                candidate_receipt_signer_identity,
            )
            if candidate_receipt is not None
            and candidate_receipt_signature is not None
            and candidate_receipt_allowed_signers is not None
            and candidate_receipt_signer_identity is not None
            else None
        )

        candidate_promotion_inputs = (
            candidate_promotion_statement,
            candidate_promotion_signature,
            candidate_promotion_allowed_signers,
            candidate_promotion_signer_identity,
        )
        if any(item is not None for item in candidate_promotion_inputs) and not all(
            item is not None for item in candidate_promotion_inputs
        ):
            raise ValueError(
                "all candidate promotion/signature/trust options are required together"
            )
        candidate_promotion_authorization = (
            authorize_candidate_promotion_statement(
                candidate_promotion_statement,
                candidate_promotion_signature,
                candidate_promotion_allowed_signers,
                candidate_promotion_signer_identity,
            )
            if candidate_promotion_statement is not None
            and candidate_promotion_signature is not None
            and candidate_promotion_allowed_signers is not None
            and candidate_promotion_signer_identity is not None
            else None
        )

        corpus_construction_inputs = (
            corpus_construction_receipt,
            corpus_construction_signature,
            corpus_construction_allowed_signers,
            corpus_construction_signer_identity,
        )
        if any(item is not None for item in corpus_construction_inputs) and not all(
            item is not None for item in corpus_construction_inputs
        ):
            raise ValueError(
                "all corpus construction receipt/signature/trust options are required together"
            )
        corpus_construction_authorization = (
            authorize_corpus_construction_receipt(
                corpus_construction_receipt,
                corpus_construction_signature,
                corpus_construction_allowed_signers,
                corpus_construction_signer_identity,
            )
            if corpus_construction_receipt is not None
            and corpus_construction_signature is not None
            and corpus_construction_allowed_signers is not None
            and corpus_construction_signer_identity is not None
            else None
        )

        corpus_freeze_inputs = (
            corpus_freeze_statement,
            corpus_freeze_signature,
            corpus_freeze_allowed_signers,
            corpus_freeze_signer_identity,
        )
        if any(item is not None for item in corpus_freeze_inputs) and not all(
            item is not None for item in corpus_freeze_inputs
        ):
            raise ValueError(
                "all corpus-freeze statement/signature/trust options are required together"
            )
        corpus_freeze_authorization = (
            authorize_corpus_freeze_statement(
                corpus_freeze_statement,
                corpus_freeze_signature,
                corpus_freeze_allowed_signers,
                corpus_freeze_signer_identity,
            )
            if corpus_freeze_statement is not None
            and corpus_freeze_signature is not None
            and corpus_freeze_allowed_signers is not None
            and corpus_freeze_signer_identity is not None
            else None
        )

        pilot_evidence_inputs = (
            pilot_evidence_statement,
            pilot_evidence_signature,
            pilot_evidence_allowed_signers,
            pilot_evidence_signer_identity,
        )
        if any(item is not None for item in pilot_evidence_inputs) and not all(
            item is not None for item in pilot_evidence_inputs
        ):
            raise ValueError(
                "all pilot evidence statement/signature/trust options are required together"
            )
        pilot_authorization = (
            authorize_pilot_evidence_statement(
                pilot_evidence_statement,
                pilot_evidence_signature,
                pilot_evidence_allowed_signers,
                pilot_evidence_signer_identity,
            )
            if pilot_evidence_statement is not None
            and pilot_evidence_signature is not None
            and pilot_evidence_allowed_signers is not None
            and pilot_evidence_signer_identity is not None
            else None
        )

        conformance_counts = {
            len(conformance_statement),
            len(conformance_signature),
            len(conformance_allowed_signers),
            len(conformance_signer_identity),
        }
        if len(conformance_counts) != 1:
            raise ValueError("conformance statement/signature/trust options must have equal counts")
        conformance_inputs = zip(
            conformance_statement,
            conformance_signature,
            conformance_allowed_signers,
            conformance_signer_identity,
            strict=True,
        )
        conformance_authorizations = tuple(
            authorize_conformance_statement(
                statement,
                statement_signature,
                statement_allowed_signers,
                statement_identity,
            )
            for (
                statement,
                statement_signature,
                statement_allowed_signers,
                statement_identity,
            ) in conformance_inputs
        )

        baseline_verification_counts = {
            len(baseline_verification_statement),
            len(baseline_verification_signature),
            len(baseline_verification_allowed_signers),
            len(baseline_verification_signer_identity),
        }
        if len(baseline_verification_counts) != 1:
            raise ValueError(
                "baseline verification statement/signature/trust options must have equal counts"
            )
        baseline_verification_inputs = zip(
            baseline_verification_statement,
            baseline_verification_signature,
            baseline_verification_allowed_signers,
            baseline_verification_signer_identity,
            strict=True,
        )
        baseline_authorizations = tuple(
            authorize_baseline_verification_statement(
                statement,
                statement_signature,
                statement_allowed_signers,
                statement_identity,
            )
            for (
                statement,
                statement_signature,
                statement_allowed_signers,
                statement_identity,
            ) in baseline_verification_inputs
        )

        release_evidence_inputs = (
            release_evidence_statement,
            release_evidence_signature,
            release_evidence_allowed_signers,
            release_evidence_signer_identity,
        )
        if any(item is not None for item in release_evidence_inputs) and not all(
            item is not None for item in release_evidence_inputs
        ):
            raise ValueError(
                "all release evidence statement/signature/trust options are required together"
            )
        release_evidence_authorization = (
            authorize_release_evidence_statement(
                release_evidence_statement,
                release_evidence_signature,
                release_evidence_allowed_signers,
                release_evidence_signer_identity,
            )
            if release_evidence_statement is not None
            and release_evidence_signature is not None
            and release_evidence_allowed_signers is not None
            and release_evidence_signer_identity is not None
            else None
        )

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
        if authorized_protocol is not None and loaded.protocol != authorized_protocol:
            raise ValueError("signed protocol differs from the release submission protocol")

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
        public_reproduction_inputs = (
            public_reproduction_verification_statement,
            public_reproduction_verification_signature,
        )
        if any(item is not None for item in public_reproduction_inputs) and not all(
            item is not None for item in public_reproduction_inputs
        ):
            raise ValueError(
                "public reproduction verification statement and signature are required together"
            )
        public_reproduction_authorization = None
        if all(item is not None for item in public_reproduction_inputs):
            if reproduction_authorization is None:
                raise ValueError(
                    "public reproduction verification requires a signed reproduction statement"
                )
            if verifier_allowed_signers is None or verifier_identity is None:
                raise ValueError("public reproduction verification requires verifier trust options")
            assert public_reproduction_verification_statement is not None
            assert public_reproduction_verification_signature is not None
            public_reproduction_authorization = (
                authorize_public_reproduction_verification_statement(
                    public_reproduction_verification_statement,
                    public_reproduction_verification_signature,
                    verifier_allowed_signers,
                    verifier_identity,
                )
            )
        gate = evaluate_benchmark_release(
            loaded,
            protocol_authorization=protocol_authorization,
            candidate_validation_authorization=candidate_validation_authorization,
            candidate_promotion_authorization=candidate_promotion_authorization,
            corpus_construction_authorization=corpus_construction_authorization,
            corpus_freeze_authorization=corpus_freeze_authorization,
            pilot_authorization=pilot_authorization,
            baseline_authorizations=baseline_authorizations,
            conformance_authorizations=conformance_authorizations,
            authorization=authorization,
            release_evidence_authorization=release_evidence_authorization,
            reproduction_authorization=reproduction_authorization,
            public_reproduction_authorization=public_reproduction_authorization,
        )
    except (
        CorpusConstructionError,
        OSError,
        PublicReproductionVerificationError,
        ValueError,
        ValidationError,
        ProtocolSignatureError,
    ) as exc:
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
        f"{gate.metrics.conformance_environments} conformance environments, "
        f"{gate.metrics.cross_machine_reproductions} cross-machine reproductions"
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


@benchmark_commands.command(name="reproduction-diff")
@click.argument("target", type=click.Path(path_type=Path))
@click.argument("reproduced", type=click.Path(path_type=Path))
@click.option("--output", type=click.Path(path_type=Path), required=True)
def reproduction_diff(target: Path, reproduced: Path, output: Path) -> None:
    """Create an immutable automatic discrepancy ledger from two verified reports."""
    try:
        template = build_reproduction_diff(
            _load_private_report(target),
            _load_private_report(reproduced),
        )
        write_reproduction_diff(output, template)
    except (
        OSError,
        UnicodeDecodeError,
        ValidationError,
        ReportMismatchError,
        ReproductionBuilderError,
        ValueError,
    ) as exc:
        raise click.ClickException("reproduction diff construction failed") from exc
    click.echo("automatic reproduction discrepancy ledger created")


def _load_report_path(path: Path) -> Report:
    """Load a report file or a reproducibility directory without trusting its numbers."""
    source = path / "report.json" if path.is_dir() else path
    return load_report(source.read_text(encoding="utf-8"))


def _load_private_report(path: Path) -> Report:
    """Load exact report bytes without following links or echoing a private path."""
    content = _read_private_regular_file(path, label="report")
    return load_report(content.decode("utf-8"))


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


@benchmark_commands.command(name="build-baseline-record")
@click.option("--configuration-id", required=True)
@click.option(
    "--corpus-record",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option(
    "--public-bundle",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option(
    "--escrow-bundle",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option(
    "--forbidden-source",
    type=click.Path(path_type=Path),
    multiple=True,
    required=True,
)
@click.option(
    "--marker-file",
    type=click.Path(path_type=Path),
    multiple=True,
    required=True,
)
@click.option(
    "--allowed-signers",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option("--signer-identity", required=True)
@click.option(
    "--machine-identity",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option("--machine-attestation", type=click.Path(path_type=Path), required=True)
@click.option(
    "--machine-attestation-signature",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option(
    "--machine-attestation-allowed-signers",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option("--machine-attestation-signer-identity", required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def build_baseline_record(
    configuration_id: str,
    corpus_record: Path,
    public_bundle: Path,
    escrow_bundle: Path,
    forbidden_source: tuple[Path, ...],
    marker_file: tuple[Path, ...],
    allowed_signers: Path,
    signer_identity: str,
    machine_identity: Path,
    machine_attestation: Path,
    machine_attestation_signature: Path,
    machine_attestation_allowed_signers: Path,
    machine_attestation_signer_identity: str,
    output: Path,
) -> None:
    """Build a baseline record only from mechanically verified artifact bytes."""
    try:
        corpus = _load_sealed_corpus_record(corpus_record)
        policy = _public_leakage_policy(forbidden_source, marker_file)
        record = build_baseline_configuration_record(
            configuration_id,
            corpus=corpus,
            public_bundle=public_bundle,
            escrow_bundle=escrow_bundle,
            leakage_policy=policy,
            protocol_allowed_signers=allowed_signers,
            protocol_signer_identity=signer_identity,
            machine_workflow_evidence=MachineWorkflowEvidencePaths(
                identity_artifact=machine_identity,
                attestation=machine_attestation,
                signature=machine_attestation_signature,
                allowed_signers=machine_attestation_allowed_signers,
                signer_identity=machine_attestation_signer_identity,
            ),
        )
        write_baseline_configuration_record(output, record)
    except (BaselineRecordError, EvidenceBundleError) as exc:
        raise click.ClickException(str(exc)) from exc
    except (OSError, UnicodeDecodeError, ValidationError, ValueError, yaml.YAMLError) as exc:
        raise click.ClickException("baseline record input is invalid") from exc
    click.echo("baseline configuration record created from verified artifacts")


@benchmark_commands.command(name="build-baseline-verification")
@click.option("--configuration-id", required=True)
@click.option("--baseline-record", type=click.Path(path_type=Path), required=True)
@click.option("--corpus-record", type=click.Path(path_type=Path), required=True)
@click.option("--public-bundle", type=click.Path(path_type=Path), required=True)
@click.option("--escrow-bundle", type=click.Path(path_type=Path), required=True)
@click.option(
    "--forbidden-source",
    type=click.Path(path_type=Path),
    multiple=True,
    required=True,
)
@click.option(
    "--marker-file",
    type=click.Path(path_type=Path),
    multiple=True,
    required=True,
)
@click.option("--protocol-allowed-signers", type=click.Path(path_type=Path), required=True)
@click.option("--protocol-signer-identity", required=True)
@click.option("--machine-identity", type=click.Path(path_type=Path), required=True)
@click.option("--machine-attestation", type=click.Path(path_type=Path), required=True)
@click.option(
    "--machine-attestation-signature",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option(
    "--machine-attestation-allowed-signers",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option("--machine-attestation-signer-identity", required=True)
@click.option("--statement-signer-identity", required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def build_baseline_verification(
    configuration_id: str,
    baseline_record: Path,
    corpus_record: Path,
    public_bundle: Path,
    escrow_bundle: Path,
    forbidden_source: tuple[Path, ...],
    marker_file: tuple[Path, ...],
    protocol_allowed_signers: Path,
    protocol_signer_identity: str,
    machine_identity: Path,
    machine_attestation: Path,
    machine_attestation_signature: Path,
    machine_attestation_allowed_signers: Path,
    machine_attestation_signer_identity: str,
    statement_signer_identity: str,
    output: Path,
) -> None:
    """Rebuild a baseline from exact bundles and emit its signable statement."""
    try:
        expected = _load_baseline_configuration_record(baseline_record)
        corpus = _load_sealed_corpus_record(corpus_record)
        statement = build_baseline_verification_statement(
            configuration_id,
            expected_record=expected,
            corpus=corpus,
            public_bundle=public_bundle,
            escrow_bundle=escrow_bundle,
            leakage_policy=_public_leakage_policy(forbidden_source, marker_file),
            protocol_allowed_signers=protocol_allowed_signers,
            protocol_signer_identity=protocol_signer_identity,
            machine_workflow_evidence=MachineWorkflowEvidencePaths(
                identity_artifact=machine_identity,
                attestation=machine_attestation,
                signature=machine_attestation_signature,
                allowed_signers=machine_attestation_allowed_signers,
                signer_identity=machine_attestation_signer_identity,
            ),
            signer_identity=statement_signer_identity,
        )
        write_baseline_verification_statement(output, statement)
    except (BaselineRecordError, EvidenceBundleError) as exc:
        raise click.ClickException(str(exc)) from exc
    except (OSError, UnicodeDecodeError, ValidationError, ValueError, yaml.YAMLError) as exc:
        raise click.ClickException("baseline verification input is invalid") from exc
    click.echo("baseline verification statement created from exact verified bundles")


@benchmark_commands.command(name="build-corpus-freeze-statement")
@click.option(
    "--corpus-record",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option(
    "--protocol",
    type=click.Path(path_type=Path),
    default="benchmark/protocol.yaml",
    show_default=True,
)
@click.option("--candidate-receipt", type=click.Path(path_type=Path), required=True)
@click.option(
    "--candidate-receipt-signature",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option(
    "--candidate-receipt-allowed-signers",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option("--candidate-receipt-signer-identity", required=True)
@click.option("--candidate-promotion-statement", type=click.Path(path_type=Path), required=True)
@click.option("--candidate-promotion-signature", type=click.Path(path_type=Path), required=True)
@click.option(
    "--candidate-promotion-allowed-signers",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option("--candidate-promotion-signer-identity", required=True)
@click.option("--signer-identity", required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def build_corpus_freeze_statement_command(
    corpus_record: Path,
    protocol: Path,
    candidate_receipt: Path,
    candidate_receipt_signature: Path,
    candidate_receipt_allowed_signers: Path,
    candidate_receipt_signer_identity: str,
    candidate_promotion_statement: Path,
    candidate_promotion_signature: Path,
    candidate_promotion_allowed_signers: Path,
    candidate_promotion_signer_identity: str,
    signer_identity: str,
    output: Path,
) -> None:
    """Derive a canonical freeze statement from complete machine corpus evidence."""
    try:
        corpus = _load_sealed_corpus_record(corpus_record)
        manifest = load_benchmark_protocol(protocol)
        statement = build_corpus_freeze_statement(
            corpus,
            protocol=manifest,
            candidate_receipt=candidate_receipt,
            candidate_receipt_signature=candidate_receipt_signature,
            candidate_receipt_allowed_signers=candidate_receipt_allowed_signers,
            candidate_receipt_signer_identity=candidate_receipt_signer_identity,
            candidate_promotion_statement=candidate_promotion_statement,
            candidate_promotion_signature=candidate_promotion_signature,
            candidate_promotion_allowed_signers=candidate_promotion_allowed_signers,
            candidate_promotion_signer_identity=candidate_promotion_signer_identity,
            signer_identity=signer_identity,
        )
        write_corpus_freeze_statement(output, statement)
    except BaselineRecordError as exc:
        raise click.ClickException(str(exc)) from exc
    except (OSError, UnicodeDecodeError, ValidationError, ValueError, yaml.YAMLError) as exc:
        raise click.ClickException("corpus freeze input is invalid") from exc
    click.echo("corpus freeze statement created from machine evidence")


@benchmark_commands.command(name="build-corpus-freeze-record")
@click.option("--statement", type=click.Path(path_type=Path), required=True)
@click.option("--signature", type=click.Path(path_type=Path), required=True)
@click.option("--allowed-signers", type=click.Path(path_type=Path), required=True)
@click.option("--signer-identity", required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def build_corpus_freeze_record_command(
    statement: Path,
    signature: Path,
    allowed_signers: Path,
    signer_identity: str,
    output: Path,
) -> None:
    """Derive a release record from a trusted signed corpus-freeze statement."""
    try:
        record = build_corpus_freeze_record(
            statement,
            signature,
            allowed_signers,
            signer_identity,
        )
        write_corpus_freeze_record(output, record)
    except BaselineRecordError as exc:
        raise click.ClickException(str(exc)) from exc
    except (OSError, UnicodeDecodeError, ValidationError, ValueError) as exc:
        raise click.ClickException("corpus freeze record input is invalid") from exc
    click.echo("corpus freeze record created from signed statement")


@benchmark_commands.command(name="build-reproduction-statement")
@click.option("--evaluator-id", required=True)
@click.option("--configuration-id", required=True)
@click.option("--corpus-record", type=click.Path(path_type=Path), required=True)
@click.option("--target-baseline-record", type=click.Path(path_type=Path), required=True)
@click.option("--target-public-bundle", type=click.Path(path_type=Path), required=True)
@click.option("--target-escrow-bundle", type=click.Path(path_type=Path), required=True)
@click.option("--target-machine-identity", type=click.Path(path_type=Path), required=True)
@click.option("--target-machine-attestation", type=click.Path(path_type=Path), required=True)
@click.option(
    "--target-machine-attestation-signature",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option(
    "--target-machine-allowed-signers",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option("--target-machine-signer-identity", required=True)
@click.option("--reproduced-public-bundle", type=click.Path(path_type=Path), required=True)
@click.option("--reproduced-escrow-bundle", type=click.Path(path_type=Path), required=True)
@click.option(
    "--reproduced-machine-identity",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option(
    "--reproduced-machine-attestation",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option(
    "--reproduced-machine-attestation-signature",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option(
    "--reproduced-machine-allowed-signers",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option("--reproduced-machine-signer-identity", required=True)
@click.option(
    "--forbidden-source",
    type=click.Path(path_type=Path),
    multiple=True,
    required=True,
)
@click.option(
    "--marker-file",
    type=click.Path(path_type=Path),
    multiple=True,
    required=True,
)
@click.option(
    "--protocol-allowed-signers",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option("--protocol-signer-identity", required=True)
@click.option(
    "--reproduced-report-signature",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option(
    "--evaluator-allowed-signers",
    type=click.Path(path_type=Path),
    required=True,
)
@click.option("--evaluator-signer-identity", required=True)
@click.option("--output-directory", type=click.Path(path_type=Path), required=True)
def build_reproduction_statement_command(
    evaluator_id: str,
    configuration_id: str,
    corpus_record: Path,
    target_baseline_record: Path,
    target_public_bundle: Path,
    target_escrow_bundle: Path,
    target_machine_identity: Path,
    target_machine_attestation: Path,
    target_machine_attestation_signature: Path,
    target_machine_allowed_signers: Path,
    target_machine_signer_identity: str,
    reproduced_public_bundle: Path,
    reproduced_escrow_bundle: Path,
    reproduced_machine_identity: Path,
    reproduced_machine_attestation: Path,
    reproduced_machine_attestation_signature: Path,
    reproduced_machine_allowed_signers: Path,
    reproduced_machine_signer_identity: str,
    forbidden_source: tuple[Path, ...],
    marker_file: tuple[Path, ...],
    protocol_allowed_signers: Path,
    protocol_signer_identity: str,
    reproduced_report_signature: Path,
    evaluator_allowed_signers: Path,
    evaluator_signer_identity: str,
    output_directory: Path,
) -> None:
    """Build canonical reproduction artifacts only from verified evidence."""
    try:
        corpus = _load_sealed_corpus_record(corpus_record)
        baseline = _load_baseline_configuration_record(target_baseline_record)
        policy = _public_leakage_policy(forbidden_source, marker_file)
        build_reproduction_statement(
            evaluator_id,
            configuration_id=configuration_id,
            corpus=corpus,
            target_baseline_record=baseline,
            target_public_bundle=target_public_bundle,
            target_escrow_bundle=target_escrow_bundle,
            target_machine_workflow_evidence=MachineWorkflowEvidencePaths(
                identity_artifact=target_machine_identity,
                attestation=target_machine_attestation,
                signature=target_machine_attestation_signature,
                allowed_signers=target_machine_allowed_signers,
                signer_identity=target_machine_signer_identity,
            ),
            reproduced_public_bundle=reproduced_public_bundle,
            reproduced_escrow_bundle=reproduced_escrow_bundle,
            reproduced_machine_workflow_evidence=MachineWorkflowEvidencePaths(
                identity_artifact=reproduced_machine_identity,
                attestation=reproduced_machine_attestation,
                signature=reproduced_machine_attestation_signature,
                allowed_signers=reproduced_machine_allowed_signers,
                signer_identity=reproduced_machine_signer_identity,
            ),
            leakage_policy=policy,
            protocol_allowed_signers=protocol_allowed_signers,
            protocol_signer_identity=protocol_signer_identity,
            reproduced_report_signature=reproduced_report_signature,
            evaluator_allowed_signers=evaluator_allowed_signers,
            evaluator_signer_identity=evaluator_signer_identity,
            output_directory=output_directory,
        )
    except (ReproductionBuilderError, EvidenceBundleError) as exc:
        raise click.ClickException(str(exc)) from exc
    except (OSError, UnicodeDecodeError, ValidationError, ValueError, yaml.YAMLError) as exc:
        raise click.ClickException("reproduction statement input is invalid") from exc
    click.echo("reproduction statement artifacts created from verified evidence")


@benchmark_commands.command(name="verify-public-reproduction")
@click.option("--reproduction-statement", type=click.Path(path_type=Path), required=True)
@click.option("--reproduction-signature", type=click.Path(path_type=Path), required=True)
@click.option("--verifier-allowed-signers", type=click.Path(path_type=Path), required=True)
@click.option("--verifier-identity", required=True)
@click.option("--target-baseline-record", type=click.Path(path_type=Path), required=True)
@click.option("--target-public-bundle", type=click.Path(path_type=Path), required=True)
@click.option("--reproduced-public-bundle", type=click.Path(path_type=Path), required=True)
@click.option(
    "--forbidden-source",
    type=click.Path(path_type=Path),
    multiple=True,
    required=True,
)
@click.option(
    "--marker-file",
    type=click.Path(path_type=Path),
    multiple=True,
    required=True,
)
@click.option("--protocol-allowed-signers", type=click.Path(path_type=Path), required=True)
@click.option("--protocol-signer-identity", required=True)
@click.option("--reproduced-report-signature", type=click.Path(path_type=Path), required=True)
@click.option("--comparison-manifest", type=click.Path(path_type=Path), required=True)
@click.option("--discrepancy-ledger", type=click.Path(path_type=Path), required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def verify_public_reproduction_command(
    reproduction_statement: Path,
    reproduction_signature: Path,
    verifier_allowed_signers: Path,
    verifier_identity: str,
    target_baseline_record: Path,
    target_public_bundle: Path,
    reproduced_public_bundle: Path,
    forbidden_source: tuple[Path, ...],
    marker_file: tuple[Path, ...],
    protocol_allowed_signers: Path,
    protocol_signer_identity: str,
    reproduced_report_signature: Path,
    comparison_manifest: Path,
    discrepancy_ledger: Path,
    output: Path,
) -> None:
    """Fully verify public artifacts and emit a canonical, non-secret signable handoff."""
    try:
        authorization = authorize_reproduction_statement(
            reproduction_statement,
            reproduction_signature,
            verifier_allowed_signers,
            verifier_identity,
        )
        receipt = verify_public_reproduction(
            authorization,
            target_baseline=_load_baseline_configuration_record(target_baseline_record),
            target_public_bundle=target_public_bundle,
            reproduced_public_bundle=reproduced_public_bundle,
            reproduced_public_leakage_policy=_public_leakage_policy(
                forbidden_source,
                marker_file,
            ),
            reproduced_protocol_allowed_signers=protocol_allowed_signers,
            reproduced_protocol_signer_identity=protocol_signer_identity,
            reproduced_report_signature=reproduced_report_signature,
            reproduced_report_allowed_signers=verifier_allowed_signers,
            reproduced_report_signer_identity=verifier_identity,
            comparison_manifest=comparison_manifest,
            discrepancy_ledger=discrepancy_ledger,
        )
        statement = build_public_reproduction_verification_statement(receipt)
        write_public_reproduction_verification_statement(statement, output)
    except (
        OSError,
        ProtocolSignatureError,
        PublicReproductionVerificationError,
        ValidationError,
        ValueError,
        yaml.YAMLError,
    ) as exc:
        raise click.ClickException("public reproduction verification failed") from exc
    click.echo("public reproduction verification statement created")


@benchmark_commands.command(name="build-reproduction-record")
@click.option("--statement", type=click.Path(path_type=Path), required=True)
@click.option("--signature", type=click.Path(path_type=Path), required=True)
@click.option("--allowed-signers", type=click.Path(path_type=Path), required=True)
@click.option("--signer-identity", required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def build_reproduction_record_command(
    statement: Path,
    signature: Path,
    allowed_signers: Path,
    signer_identity: str,
    output: Path,
) -> None:
    """Derive a release record from an externally signed canonical statement."""
    try:
        record = build_reproduction_record(
            statement,
            signature,
            allowed_signers,
            signer_identity,
        )
        write_reproduction_record(output, record)
    except ReproductionBuilderError as exc:
        raise click.ClickException(str(exc)) from exc
    except (OSError, UnicodeDecodeError, ValidationError, ValueError) as exc:
        raise click.ClickException("reproduction record input is invalid") from exc
    click.echo("cross-machine reproduction record created from signed statement")


def _load_sealed_corpus_record(path: Path) -> SealedCorpusRecord:
    """Load a closed corpus record without echoing its storage path on failure."""
    raw = yaml.safe_load(_read_private_regular_file(path, label="corpus record").decode("utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("corpus record root must be a mapping")
    return SealedCorpusRecord.model_validate(raw)


def _load_baseline_configuration_record(path: Path) -> BaselineConfigurationRecord:
    """Load one closed target baseline record without disclosing its path."""
    raw = yaml.safe_load(_read_private_regular_file(path, label="baseline record").decode("utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("baseline record root must be a mapping")
    return BaselineConfigurationRecord.model_validate(raw)


def _public_leakage_policy(
    forbidden_sources: tuple[Path, ...],
    marker_files: tuple[Path, ...],
) -> PublicLeakagePolicy:
    """Read sensitive markers from files so their values never appear in process arguments."""
    markers = [_read_private_marker(marker_file) for marker_file in marker_files]
    return PublicLeakagePolicy(
        forbidden_sources=forbidden_sources,
        forbidden_markers=tuple(markers),
    )


def _read_private_marker(path: Path) -> bytes:
    """Read a regular nonsymlink marker without blocking on special files."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceBundleError(
            "a marker file must be a readable regular nonsymlink file"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceBundleError("a marker file must be a readable regular nonsymlink file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    marker = b"".join(chunks).rstrip(b"\r\n")
    if not marker:
        raise EvidenceBundleError("a marker file is empty")
    return marker


def _read_private_regular_file(path: Path, *, label: str) -> bytes:
    """Read a nonempty regular nonsymlink private input without FIFO blocking."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} must be a readable regular nonsymlink file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} must be a readable regular nonsymlink file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    content = b"".join(chunks)
    if not content:
        raise ValueError(f"{label} must not be empty")
    return content


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
    benchmark_mode = False
    if config_path is not None:
        try:
            config = RunConfig.from_yaml(config_path)
        except ConfigError as exc:
            raise click.ClickException(str(exc)) from exc
        path = config.corpus
        docker = docker or config.isolation is Isolation.DOCKER
        image = config.image  # validate with the image the run will verify with, not a default
        benchmark_mode = config.benchmark_protocol_version is not None
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
            if benchmark_mode:
                box.preflight_benchmark(Path(__file__).resolve().parents[2])
            else:
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
    resolved_corpus_hash = corpus_hash(scenarios)
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
        if resolved.benchmark_protocol_version is not None:
            sandbox.preflight_benchmark(Path(__file__).resolve().parents[2])
        else:
            sandbox.preflight()
    except SandboxError as exc:
        raise click.ClickException(str(exc)) from exc

    runtime_provenance = None
    invocation_contexts: dict[tuple[str, int], InvocationContext] = {}
    if resolved.benchmark_protocol_version is not None:
        try:
            runtime_provenance = verify_runtime_provenance(
                resolved,
                adapter,
                workdir=Path.cwd(),
                repository=Path(__file__).resolve().parents[2],
                docker_runtime_identity=sandbox.docker_runtime_identity,
                verification_image_identity=sandbox.verification_image_identity,
            )
        except RuntimePreflightError as exc:
            raise click.ClickException(str(exc)) from exc
        try:
            invocation_plan = build_invocation_plan(
                config=resolved,
                corpus_hash=resolved_corpus_hash,
                runtime_provenance=runtime_provenance,
                ordered_scenario_ids=tuple(scenario.id for scenario in scenarios),
            )
        except ValueError as exc:
            raise click.ClickException(
                "benchmark invocation plan could not be constructed"
            ) from exc
        invocation_contexts = {
            (context.scenario_id, context.repetition): context for context in invocation_plan
        }

    results: list[ScenarioResult] = []
    for scenario in scenarios:
        for repetition in range(resolved.reps):
            click.echo(f"  {scenario.id} rep {repetition + 1}/{resolved.reps} ... ", nl=False)
            try:
                result = run_scenario_once(
                    scenario.directory,
                    scenario.manifest,
                    adapter,
                    repetition,
                    sandbox=sandbox,
                    artifacts_dir=package / RUNS_DIR / scenario.id / str(repetition),
                    path_root=package,
                    invocation_context=invocation_contexts.get((scenario.id, repetition)),
                )
            except AgentContainmentError as exc:
                click.echo("ABORT")
                raise click.ClickException(
                    "contained agent safety failure at "
                    f"{scenario.id} repetition {repetition + 1}/{resolved.reps}: "
                    "container termination could not be verified. Partial evidence is "
                    f"preserved at {package.resolve()}. Do not resume or splice this package."
                ) from exc
            results.append(result)
            click.echo(str(result.outcome))

    try:
        sandbox.verify_runtime_unchanged()
    except SandboxError as exc:
        raise click.ClickException(
            f"contained run runtime changed before evidence finalization: {exc}"
        ) from exc

    report_ = build_report(
        results,
        corpus_hash=resolved_corpus_hash,
        config_fingerprint=resolved.fingerprint(),
        generated_at=generated_at,
        judge_assisted=_maybe_judge(resolved),
        benchmark_metadata=resolved.benchmark_metadata(),
        benchmark_runtime_provenance=runtime_provenance,
    )
    try:
        write_repro_package(package, report_, resolved, scenarios)
    except (ClassificationReplayError, ValueError) as exc:
        raise click.ClickException("benchmark invocation evidence could not be finalized") from exc

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
            if config.benchmark_protocol_version is not None:
                box.preflight_benchmark(Path(__file__).resolve().parents[2])
            else:
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
