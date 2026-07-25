"""Fail-closed CLI coverage for artifact-derived pilot evidence."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from click.testing import CliRunner
from pydantic import BaseModel, ConfigDict

import stinger.cli as cli_module
from stinger.benchmark.signing import (
    PILOT_EVIDENCE_SIGNATURE_NAMESPACE,
    verify_pilot_evidence_statement_signature,
)
from stinger.cli import main

IDENTITY = "pilot-evidence@example.test"
ROOT = Path(__file__).resolve().parents[1]


class _StubPilotStatement(BaseModel):
    """Small closed model sufficient to exercise the real atomic statement writer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: str = "2"
    scenario_count: int = 5
    configuration_count: int = 1


@pytest.fixture
def signing_material(tmp_path: Path) -> dict[str, Path]:
    """Generate ephemeral signing material controlled entirely by the test."""
    private_key = tmp_path / "pilot-signing-key"
    generated = subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "stinger-pilot-test-only",
            "-f",
            str(private_key),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    if generated.returncode != 0:
        pytest.fail(f"could not generate test signing key: {generated.stderr}")
    public_key = private_key.with_suffix(".pub").read_text(encoding="utf-8").strip()
    allowed_signers = tmp_path / "pilot.allowed-signers"
    allowed_signers.write_text(f"{IDENTITY} {public_key}\n", encoding="utf-8")
    return {
        "private_key": private_key,
        "allowed_signers": allowed_signers,
    }


def test_sign_pilot_evidence_cli_signs_exact_bytes_and_refuses_overwrite(
    tmp_path: Path,
    signing_material: dict[str, Path],
) -> None:
    """The CLI creates one dedicated signature and never replaces it."""
    statement = tmp_path / "pilot-evidence.json"
    statement.write_bytes(b'{"format_version":"2","scenario_count":120}\n')
    command = [
        "benchmark",
        "sign-pilot-evidence",
        str(statement),
        "--private-key",
        str(signing_material["private_key"]),
    ]

    first = CliRunner().invoke(main, command)

    assert first.exit_code == 0, first.output
    signature = Path(f"{statement}.sig")
    assert signature.is_file()
    verification = verify_pilot_evidence_statement_signature(
        statement,
        signature,
        signing_material["allowed_signers"],
        IDENTITY,
    )
    assert verification.namespace == PILOT_EVIDENCE_SIGNATURE_NAMESPACE

    signature_bytes = signature.read_bytes()
    second = CliRunner().invoke(main, command)

    assert second.exit_code != 0
    assert "refusing to overwrite" in second.output
    assert signature.read_bytes() == signature_bytes


def test_release_check_pilot_options_are_all_or_nothing_without_path_disclosure(
    tmp_path: Path,
) -> None:
    """One pilot option cannot reach authorization or disclose its sensitive path."""
    submission = tmp_path / "candidate-submission.yaml"
    submission.write_bytes((ROOT / "benchmark" / "candidate-submission.yaml").read_bytes())
    sensitive = tmp_path / "private-sealed-review" / "pilot-evidence.json"
    sensitive.parent.mkdir()
    sensitive.write_text("{}\n", encoding="utf-8")

    result = CliRunner().invoke(
        main,
        [
            "benchmark",
            "release-check",
            str(submission),
            "--pilot-evidence-statement",
            str(sensitive),
        ],
    )

    assert result.exit_code != 0
    assert (
        "all pilot evidence statement/signature/trust options are required together"
        in result.output
    )
    assert str(sensitive) not in result.output
    assert str(sensitive.parent) not in result.output


def test_build_pilot_evidence_rejects_unequal_repeated_option_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Alias/run/trust vectors must be one exact positional grid."""
    inputs = _build_inputs(tmp_path)

    def forbidden_builder(**kwargs: Any) -> object:
        del kwargs
        pytest.fail("pilot builder must not run after unequal option counts")

    monkeypatch.setattr(cli_module, "build_pilot_evidence_statement", forbidden_builder)
    result = CliRunner().invoke(
        main,
        _build_command(inputs, aliases=("anonymous-0000000000000001", "extra-alias")),
    )

    assert result.exit_code != 0
    assert "pilot alias, bundle, and protocol-trust options must have equal counts" in (
        result.output
    )
    assert not inputs["output"].exists()


def test_build_pilot_evidence_rejects_caller_authored_selection_protocol(
    tmp_path: Path,
) -> None:
    arbitrary = tmp_path / "post-hoc-selection.txt"
    arbitrary.write_text("favor one provider\n", encoding="utf-8")

    result = CliRunner().invoke(
        main,
        [
            "benchmark",
            "build-pilot-evidence",
            "--selection-protocol",
            str(arbitrary),
        ],
    )

    assert result.exit_code != 0
    assert "No such option '--selection-protocol'" in result.output


def test_build_pilot_evidence_cli_never_overwrites_existing_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The CLI retains the first canonical file when a later build targets it."""
    inputs = _build_inputs(tmp_path)
    statement = _StubPilotStatement()

    monkeypatch.setattr(cli_module, "_load_sealed_corpus_record", lambda path: object())
    monkeypatch.setattr(
        cli_module,
        "_public_leakage_policy",
        lambda forbidden_sources, marker_files: object(),
    )
    monkeypatch.setattr(
        cli_module,
        "build_pilot_evidence_statement",
        lambda **kwargs: SimpleNamespace(statement=statement),
    )
    command = _build_command(inputs, aliases=("anonymous-0000000000000001",))

    first = CliRunner().invoke(main, command)

    assert first.exit_code == 0, first.output
    original = inputs["output"].read_bytes()
    assert original.endswith(b"\n")

    second = CliRunner().invoke(main, command)

    assert second.exit_code != 0
    assert "pilot evidence construction failed: pilot statement output already exists" in (
        second.output
    )
    assert inputs["output"].read_bytes() == original


def _build_inputs(tmp_path: Path) -> dict[str, Path]:
    """Create harmless paths that satisfy Click before focused CLI assertions."""
    inputs = {
        "corpus": tmp_path / "sealed-corpus-record.json",
        "candidate_receipt": tmp_path / "candidate-receipt.json",
        "public_bundle": tmp_path / "public-bundle",
        "escrow_bundle": tmp_path / "escrow-bundle",
        "allowed_signers": tmp_path / "protocol.allowed-signers",
        "forbidden_source": tmp_path / "sealed-source",
        "marker_file": tmp_path / "markers.txt",
        "output": tmp_path / "published" / "pilot-evidence.json",
    }
    for key in ("public_bundle", "escrow_bundle", "forbidden_source"):
        inputs[key].mkdir()
    for key in (
        "corpus",
        "candidate_receipt",
        "allowed_signers",
        "marker_file",
    ):
        inputs[key].write_text("{}\n", encoding="utf-8")
    return inputs


def _build_command(inputs: dict[str, Path], *, aliases: tuple[str, ...]) -> list[str]:
    """Render the build command with exactly one run artifact/trust tuple."""
    command = [
        "benchmark",
        "build-pilot-evidence",
        "--corpus-record",
        str(inputs["corpus"]),
        "--candidate-receipt",
        str(inputs["candidate_receipt"]),
    ]
    for alias in aliases:
        command.extend(("--configuration-alias", alias))
    command.extend(
        (
            "--public-bundle",
            str(inputs["public_bundle"]),
            "--escrow-bundle",
            str(inputs["escrow_bundle"]),
            "--protocol-allowed-signers",
            str(inputs["allowed_signers"]),
            "--protocol-signer-identity",
            "protocol-signer@example.test",
            "--forbidden-source",
            str(inputs["forbidden_source"]),
            "--marker-file",
            str(inputs["marker_file"]),
            "--output",
            str(inputs["output"]),
        )
    )
    return command
