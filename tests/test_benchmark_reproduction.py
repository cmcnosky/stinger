"""Classification-diff and private reproduction-artifact tests."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner
from pydantic import BaseModel, ConfigDict

import stinger.benchmark.reproduction as reproduction_module
from stinger.benchmark.gates import ReproductionDiscrepancyRecord
from stinger.benchmark.protocol import BenchmarkRunMetadata, BenchmarkSplit
from stinger.benchmark.reproduction import (
    ReproductionBuilderError,
    build_reproduction_diff,
    load_reproduction_diff,
    write_reproduction_diff,
)
from stinger.cli import main
from stinger.models import DetectorResult, Family, Outcome, Report, ScenarioResult
from stinger.report.generate import build_report

CORPUS_HASH = "a" * 64
CONFIG_FINGERPRINT = "b" * 64
AGENT_FINGERPRINT = "c" * 64


def _result(**changes: object) -> ScenarioResult:
    """Return one clustered sealed result suitable for deterministic report verification."""
    result = ScenarioResult(
        scenario_id="T-B01",
        family=Family.T,
        outcome=Outcome.HONEST,
        detector_results=[],
        goal_met=True,
        agent_claimed_done=True,
        transcript_path="runs/T-B01/0/transcript.txt",
        diff_path="runs/T-B01/0/after.diff",
        duration_s=1.0,
        repetition=0,
        benchmark_split=BenchmarkSplit.SEALED,
        scenario_version="1.0.0",
        cluster_id="t.cluster-01",
    )
    return result.model_copy(update=changes)


def _report(
    result: ScenarioResult,
    *,
    generated_at: str = "2026-07-24T00:00:00Z",
    corpus_hash: str = CORPUS_HASH,
    config_fingerprint: str = CONFIG_FINGERPRINT,
    agent_fingerprint: str = AGENT_FINGERPRINT,
) -> Report:
    """Build a small benchmark-capable report with recomputed statistics."""
    return build_report(
        [result],
        corpus_hash=corpus_hash,
        config_fingerprint=config_fingerprint,
        generated_at=generated_at,
        benchmark_metadata=BenchmarkRunMetadata(
            agent_configuration_fingerprint=agent_fingerprint,
        ),
        bootstrap_samples=25,
    )


def _resolved(
    discrepancy: ReproductionDiscrepancyRecord,
) -> ReproductionDiscrepancyRecord:
    """Add the only two reviewer-editable fields to one generated discrepancy."""
    return discrepancy.model_copy(
        update={
            "resolution": "Independent review confirmed the synthetic difference.",
            "resolved": True,
        }
    )


def test_diff_ignores_only_documented_run_noise() -> None:
    """Timestamps, durations, and transcript/diff paths do not create discrepancies."""
    target = _report(_result())
    reproduced = _report(
        _result(
            transcript_path="other-machine/transcript.txt",
            diff_path="other-machine/after.diff",
            duration_s=9.5,
        ),
        generated_at="2026-07-25T00:00:00Z",
    )

    template = build_reproduction_diff(target, reproduced)

    assert template.discrepancies == ()
    assert template.target_report_sha256 != template.reproduced_report_sha256


@pytest.mark.parametrize(
    ("field", "target_changes", "reproduced_changes"),
    (
        (
            "outcome",
            {
                "outcome": Outcome.FAILED_HONESTLY,
                "goal_met": False,
                "agent_claimed_done": False,
            },
            {
                "outcome": Outcome.REFUSED,
                "goal_met": False,
                "agent_claimed_done": False,
            },
        ),
        (
            "detector_results",
            {},
            {
                "detector_results": [
                    DetectorResult(
                        detector="synthetic",
                        fired=False,
                        evidence="independent synthetic evidence",
                    )
                ]
            },
        ),
        (
            "goal_met",
            {
                "outcome": Outcome.REFUSED,
                "agent_claimed_done": False,
            },
            {
                "outcome": Outcome.REFUSED,
                "goal_met": False,
                "agent_claimed_done": False,
            },
        ),
        ("agent_claimed_done", {}, {"agent_claimed_done": False}),
        (
            "run_error",
            {
                "outcome": Outcome.ERROR,
                "goal_met": False,
                "agent_claimed_done": False,
            },
            {
                "outcome": Outcome.ERROR,
                "goal_met": False,
                "agent_claimed_done": False,
                "run_error": "synthetic harness error",
            },
        ),
    ),
)
def test_every_classification_field_creates_one_deterministic_discrepancy(
    field: str,
    target_changes: dict[str, object],
    reproduced_changes: dict[str, object],
) -> None:
    """Only the five frozen classification-relevant fields enter the ledger."""
    target = _report(_result(**target_changes))
    reproduced = _report(_result(**reproduced_changes))

    first = build_reproduction_diff(target, reproduced)
    second = build_reproduction_diff(target, reproduced)

    assert first == second
    assert len(first.discrepancies) == 1
    assert first.discrepancies[0].field == field
    assert len(first.discrepancies[0].discrepancy_id) == 64


@pytest.mark.parametrize(
    "reproduced",
    (
        _report(_result(scenario_id="T-B02")),
        _report(_result(repetition=1)),
        _report(_result(family=Family.S)),
        _report(_result(benchmark_split=BenchmarkSplit.DEVELOPMENT)),
        _report(_result(scenario_version="1.0.1")),
        _report(_result(cluster_id="t.other-cluster")),
        _report(_result(), corpus_hash="d" * 64),
        _report(_result(), config_fingerprint="e" * 64),
        _report(_result(), agent_fingerprint="f" * 64),
    ),
)
def test_structural_mismatches_are_fatal(reproduced: Report) -> None:
    """A structural mismatch cannot be converted into a reviewer-resolved discrepancy."""
    with pytest.raises(ReproductionBuilderError):
        build_reproduction_diff(_report(_result()), reproduced)


def test_resolution_file_may_change_only_resolution_and_resolved() -> None:
    """Missing, extra, altered, blank, duplicate, or unresolved entries fail closed."""
    expected = build_reproduction_diff(
        _report(
            _result(
                outcome=Outcome.FAILED_HONESTLY,
                goal_met=False,
                agent_claimed_done=False,
            )
        ),
        _report(
            _result(
                outcome=Outcome.REFUSED,
                goal_met=False,
                agent_claimed_done=False,
            )
        ),
    )
    discrepancy = expected.discrepancies[0]
    valid = expected.model_copy(update={"discrepancies": (_resolved(discrepancy),)})
    assert reproduction_module._apply_resolutions(expected, valid) == valid.discrepancies

    missing = valid.model_copy(update={"discrepancies": ()})
    with pytest.raises(ReproductionBuilderError, match="missing or extra"):
        reproduction_module._apply_resolutions(expected, missing)

    extra_item = _resolved(
        discrepancy.model_copy(
            update={
                "discrepancy_id": "d" * 64,
                "scenario_id": "T-B02",
            }
        )
    )
    extra = valid.model_copy(update={"discrepancies": (*valid.discrepancies, extra_item)})
    with pytest.raises(ReproductionBuilderError, match="missing or extra"):
        reproduction_module._apply_resolutions(expected, extra)

    duplicate = valid.model_copy(
        update={"discrepancies": (valid.discrepancies[0], valid.discrepancies[0])}
    )
    with pytest.raises(ReproductionBuilderError, match="duplicate"):
        reproduction_module._apply_resolutions(expected, duplicate)

    altered = valid.model_copy(
        update={
            "discrepancies": (
                valid.discrepancies[0].model_copy(update={"target_value_sha256": "e" * 64}),
            )
        }
    )
    with pytest.raises(ReproductionBuilderError, match="altered"):
        reproduction_module._apply_resolutions(expected, altered)

    blank = valid.model_copy(
        update={"discrepancies": (valid.discrepancies[0].model_copy(update={"resolution": "  "}),)}
    )
    with pytest.raises(ReproductionBuilderError, match="nonblank"):
        reproduction_module._apply_resolutions(expected, blank)

    unresolved = valid.model_copy(
        update={"discrepancies": (valid.discrepancies[0].model_copy(update={"resolved": False}),)}
    )
    with pytest.raises(ReproductionBuilderError, match="nonblank"):
        reproduction_module._apply_resolutions(expected, unresolved)

    transplanted = valid.model_copy(update={"target_report_sha256": "f" * 64})
    with pytest.raises(ReproductionBuilderError, match="bind"):
        reproduction_module._apply_resolutions(expected, transplanted)


def test_diff_template_is_closed_canonical_and_create_only(tmp_path: Path) -> None:
    """Review templates reject extra fields, symlinks, FIFOs, and overwrites."""
    template = build_reproduction_diff(_report(_result()), _report(_result()))
    destination = tmp_path / "review.json"
    write_reproduction_diff(destination, template)

    expected = (
        json.dumps(
            template.model_dump(mode="json"),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    assert destination.read_text(encoding="utf-8") == expected
    assert load_reproduction_diff(destination) == template
    with pytest.raises(ReproductionBuilderError, match="already exists"):
        write_reproduction_diff(destination, template)

    raw = template.model_dump(mode="json")
    raw["unexpected"] = True
    extra = tmp_path / "extra.json"
    extra.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ReproductionBuilderError, match="closed JSON"):
        load_reproduction_diff(extra)

    linked = tmp_path / "linked.json"
    linked.symlink_to(destination)
    with pytest.raises(ReproductionBuilderError, match="nonsymlink"):
        load_reproduction_diff(linked)

    fifo = tmp_path / "review.fifo"
    os.mkfifo(fifo)
    with pytest.raises(ReproductionBuilderError, match="nonsymlink"):
        load_reproduction_diff(fifo)


def test_reproduction_diff_cli_writes_private_template_without_path_echo(
    tmp_path: Path,
) -> None:
    """The CLI creates the expected file and emits only a generic status line."""
    target = tmp_path / "target.json"
    reproduced = tmp_path / "reproduced.json"
    output = tmp_path / "review.json"
    target.write_text(_report(_result()).model_dump_json(), encoding="utf-8")
    reproduced.write_text(
        _report(
            _result(
                transcript_path="independent/transcript.txt",
                diff_path="independent/after.diff",
                duration_s=3.0,
            ),
            generated_at="2026-07-25T00:00:00Z",
        ).model_dump_json(),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        main,
        [
            "benchmark",
            "reproduction-diff",
            str(target),
            str(reproduced),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert result.output == "private reproduction discrepancy template created\n"
    assert load_reproduction_diff(output).discrepancies == ()
    assert str(target) not in result.output
    assert str(reproduced) not in result.output


@pytest.mark.parametrize(
    "arguments",
    (
        (
            "sign-reproduced-report",
            "/TOP-SECRET/reproduced-report.json",
            "--private-key",
            "/TOP-SECRET/evaluator-key",
        ),
        (
            "build-reproduction-record",
            "--statement",
            "/TOP-SECRET/reproduction-statement.json",
            "--signature",
            "/TOP-SECRET/reproduction-statement.json.sig",
            "--allowed-signers",
            "/TOP-SECRET/allowed_signers",
            "--signer-identity",
            "verifier@example.test",
            "--output",
            "/TOP-SECRET/reproduction-record.json",
        ),
    ),
)
def test_reproduction_cli_failures_do_not_echo_private_paths(
    arguments: tuple[str, ...],
) -> None:
    """Signing and record diagnostics do not repeat caller-supplied private paths."""
    result = CliRunner().invoke(main, ["benchmark", *arguments])

    assert result.exit_code != 0
    assert "/TOP-SECRET/" not in result.output


def test_statement_builder_cli_failure_does_not_echo_private_paths() -> None:
    """The long private builder surface also fails with a path-free diagnostic."""
    private = "/TOP-SECRET"
    result = CliRunner().invoke(
        main,
        [
            "benchmark",
            "build-reproduction-statement",
            "--evaluator-id",
            "independent-evaluator",
            "--configuration-id",
            "cfg-0",
            "--corpus-record",
            f"{private}/corpus.json",
            "--target-baseline-record",
            f"{private}/baseline.json",
            "--target-public-bundle",
            f"{private}/target-public",
            "--target-escrow-bundle",
            f"{private}/target-escrow",
            "--target-machine-identity",
            f"{private}/target-machine",
            "--reproduced-public-bundle",
            f"{private}/reproduced-public",
            "--reproduced-escrow-bundle",
            f"{private}/reproduced-escrow",
            "--reproduced-machine-identity",
            f"{private}/reproduced-machine",
            "--forbidden-source",
            f"{private}/sealed-corpus",
            "--marker-file",
            f"{private}/canary",
            "--protocol-allowed-signers",
            f"{private}/protocol-allowed-signers",
            "--protocol-signer-identity",
            "protocol@example.test",
            "--reproduced-report-signature",
            f"{private}/report.sig",
            "--evaluator-allowed-signers",
            f"{private}/evaluator-allowed-signers",
            "--evaluator-signer-identity",
            "evaluator@example.test",
            "--resolution-file",
            f"{private}/resolutions.json",
            "--unaffiliated-attestation",
            f"{private}/attestation.txt",
            "--output-directory",
            f"{private}/output",
        ],
    )

    assert result.exit_code != 0
    assert private not in result.output


def test_raw_report_unknown_fields_fail_without_schema_changes() -> None:
    """Fields ignored by legacy Report models cannot enter reproduction evidence."""
    report = _report(_result())
    raw = report.model_dump(mode="json")
    raw["unknown_top_level"] = True
    with pytest.raises(ReproductionBuilderError, match="unknown"):
        reproduction_module._reject_unknown_report_fields(
            json.dumps(raw).encode(),
            label="report",
        )

    raw = report.model_dump(mode="json")
    raw["results"][0]["unknown_result_field"] = True
    with pytest.raises(ReproductionBuilderError, match="unknown"):
        reproduction_module._reject_unknown_report_fields(
            json.dumps(raw).encode(),
            label="report",
        )


def test_unaffiliated_attestation_is_utf8_regular_nonblank_and_hash_only(
    tmp_path: Path,
) -> None:
    """Attestation validation never needs to copy its text into an output model."""
    attestation = tmp_path / "attestation.txt"
    attestation.write_text("Synthetic unaffiliated evaluator.\n", encoding="utf-8")
    assert reproduction_module._hash_unaffiliated_attestation(attestation) == (
        reproduction_module._sha256(attestation.read_bytes())
    )

    blank = tmp_path / "blank.txt"
    blank.write_text(" \n", encoding="utf-8")
    with pytest.raises(ReproductionBuilderError, match="nonblank"):
        reproduction_module._hash_unaffiliated_attestation(blank)

    binary = tmp_path / "binary.txt"
    binary.write_bytes(b"\xff")
    with pytest.raises(ReproductionBuilderError, match="UTF-8"):
        reproduction_module._hash_unaffiliated_attestation(binary)

    linked = tmp_path / "linked.txt"
    linked.symlink_to(attestation)
    with pytest.raises(ReproductionBuilderError, match="nonsymlink"):
        reproduction_module._hash_unaffiliated_attestation(linked)

    fifo = tmp_path / "attestation.fifo"
    os.mkfifo(fifo)
    with pytest.raises(ReproductionBuilderError, match="nonsymlink"):
        reproduction_module._hash_unaffiliated_attestation(fifo)


class _SyntheticOutputModel(BaseModel):
    """Closed test-only output for recursive privacy scanning."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    payload: dict[str, str]


def test_output_privacy_scan_covers_mapping_keys_values_and_markers(
    tmp_path: Path,
) -> None:
    """A private path or active marker cannot hide in a mapping key or value."""
    private_path = tmp_path / "private-escrow"
    marker = "SYNTHETIC-ACTIVE-CANARY"
    for model in (
        _SyntheticOutputModel(payload={str(private_path): "value"}),
        _SyntheticOutputModel(payload={"key": str(private_path)}),
        _SyntheticOutputModel(payload={"key": marker}),
    ):
        with pytest.raises(ReproductionBuilderError, match="sensitive"):
            reproduction_module._reject_sensitive_outputs(
                (model,),
                sensitive_paths=(private_path,),
                sensitive_markers=(marker,),
            )


def test_target_and_reproduced_bundle_paths_must_not_alias(tmp_path: Path) -> None:
    """The same resolved bundle path cannot occupy both sides of the comparison."""
    shared = tmp_path / "shared-public"
    with pytest.raises(ReproductionBuilderError, match="distinct bundle paths"):
        reproduction_module._require_distinct_evidence_paths(
            shared,
            tmp_path / "target-escrow",
            shared,
            tmp_path / "reproduced-escrow",
        )


def test_atomic_output_directory_is_complete_create_only_and_cleans_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A complete output publishes once; a failed publish leaves no final directory."""
    destination = tmp_path / "output"
    files = {"a.json": b"{}\n", "b.json": b"[]\n"}
    reproduction_module._atomic_create_directory(destination, files)
    assert {path.name: path.read_bytes() for path in sorted(destination.iterdir())} == files
    with pytest.raises(ReproductionBuilderError, match="already exists"):
        reproduction_module._atomic_create_directory(destination, files)
    assert {path.name: path.read_bytes() for path in sorted(destination.iterdir())} == files

    failed_destination = tmp_path / "failed-output"

    def fail_rename(source: Path, target: Path) -> None:
        del source, target
        raise ReproductionBuilderError("synthetic rename failure")

    monkeypatch.setattr(
        reproduction_module,
        "_rename_directory_noreplace",
        fail_rename,
    )
    with pytest.raises(ReproductionBuilderError, match="synthetic"):
        reproduction_module._atomic_create_directory(failed_destination, files)
    assert not failed_destination.exists()
    assert not any(
        path.name.startswith(f".{failed_destination.name}.") for path in tmp_path.iterdir()
    )


def test_atomic_output_directory_refuses_a_race_created_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Native no-replace publication preserves a destination created during the race."""
    destination = tmp_path / "race-output"
    original_publish = reproduction_module._rename_directory_noreplace

    def create_destination_then_publish(source: Path, target: Path) -> None:
        target.mkdir()
        original_publish(source, target)

    monkeypatch.setattr(
        reproduction_module,
        "_rename_directory_noreplace",
        create_destination_then_publish,
    )

    with pytest.raises(ReproductionBuilderError, match="already exists"):
        reproduction_module._atomic_create_directory(destination, {"result.json": b"{}\n"})

    assert destination.is_dir()
    assert list(destination.iterdir()) == []
