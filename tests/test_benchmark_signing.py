"""Detached trust verification for the frozen benchmark protocol."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from stinger.benchmark.gates import (
    PublicationIssueCode,
    authorize_benchmark_submission,
    evaluate_benchmark_release,
)
from stinger.benchmark.signing import (
    PROTOCOL_SIGNATURE_NAMESPACE,
    RELEASE_SIGNATURE_NAMESPACE,
    REPRODUCTION_SIGNATURE_NAMESPACE,
    ProtocolSignatureError,
    sign_protocol,
    sign_release_submission,
    sign_reproduction_statement,
    verify_protocol_signature,
    verify_release_submission_signature,
    verify_reproduction_statement_signature,
)
from stinger.cli import main

IDENTITY = "stinger-release@example.test"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def signing_material(tmp_path: Path) -> dict[str, Path]:
    """Generate an ephemeral Ed25519 key and verifier trust file."""
    private_key = tmp_path / "release-key"
    generated = subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "stinger-test-only",
            "-f",
            str(private_key),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    if generated.returncode != 0:
        pytest.fail(f"could not generate test signing key: {generated.stderr}")

    protocol = tmp_path / "protocol.yaml"
    protocol.write_text(
        "benchmark_protocol_version: 1.0.0\nstatus: candidate\n",
        encoding="utf-8",
    )
    public_key = private_key.with_suffix(".pub").read_text(encoding="utf-8").strip()
    allowed_signers = tmp_path / "allowed_signers"
    allowed_signers.write_text(f"{IDENTITY} {public_key}\n", encoding="utf-8")
    return {
        "private_key": private_key,
        "protocol": protocol,
        "allowed_signers": allowed_signers,
    }


class TestProtocolSigning:
    """Only a trusted identity's signature over the exact protocol passes."""

    def test_signs_and_verifies_exact_protocol_bytes(
        self, signing_material: dict[str, Path]
    ) -> None:
        signature = sign_protocol(
            signing_material["protocol"],
            signing_material["private_key"],
        )

        verification = verify_protocol_signature(
            signing_material["protocol"],
            signature,
            signing_material["allowed_signers"],
            IDENTITY,
        )

        assert verification.identity == IDENTITY
        assert verification.namespace == PROTOCOL_SIGNATURE_NAMESPACE
        assert len(verification.protocol_sha256) == 64
        assert len(verification.signature_sha256) == 64
        assert len(verification.allowed_signers_sha256) == 64

    def test_tampered_protocol_and_wrong_identity_fail_closed(
        self, signing_material: dict[str, Path]
    ) -> None:
        signature = sign_protocol(
            signing_material["protocol"],
            signing_material["private_key"],
        )
        signing_material["protocol"].write_text(
            "benchmark_protocol_version: 1.0.0\nstatus: released\n",
            encoding="utf-8",
        )

        with pytest.raises(ProtocolSignatureError, match="verification failed"):
            verify_protocol_signature(
                signing_material["protocol"],
                signature,
                signing_material["allowed_signers"],
                IDENTITY,
            )
        with pytest.raises(ProtocolSignatureError, match="verification failed"):
            verify_protocol_signature(
                signing_material["protocol"],
                signature,
                signing_material["allowed_signers"],
                "another@example.test",
            )

    def test_refuses_to_overwrite_a_signature(self, signing_material: dict[str, Path]) -> None:
        sign_protocol(signing_material["protocol"], signing_material["private_key"])

        with pytest.raises(ProtocolSignatureError, match="overwrite"):
            sign_protocol(signing_material["protocol"], signing_material["private_key"])

    def test_rejects_ambiguous_identity_or_symlinked_protocol(
        self, tmp_path: Path, signing_material: dict[str, Path]
    ) -> None:
        signature = sign_protocol(
            signing_material["protocol"],
            signing_material["private_key"],
        )
        with pytest.raises(ProtocolSignatureError, match="identity"):
            verify_protocol_signature(
                signing_material["protocol"],
                signature,
                signing_material["allowed_signers"],
                "two principals",
            )

        linked = tmp_path / "linked-protocol"
        linked.symlink_to(signing_material["protocol"])
        with pytest.raises(ProtocolSignatureError, match="real regular file"):
            verify_protocol_signature(
                linked,
                signature,
                signing_material["allowed_signers"],
                IDENTITY,
            )

    def test_cli_verifies_against_an_explicit_trust_file(
        self, signing_material: dict[str, Path]
    ) -> None:
        signature = sign_protocol(
            signing_material["protocol"],
            signing_material["private_key"],
        )

        outcome = CliRunner().invoke(
            main,
            [
                "benchmark",
                "verify-protocol",
                str(signing_material["protocol"]),
                "--signature",
                str(signature),
                "--allowed-signers",
                str(signing_material["allowed_signers"]),
                "--signer-identity",
                IDENTITY,
            ],
        )

        assert outcome.exit_code == 0, outcome.output
        assert f"signer {IDENTITY}" in outcome.output


def test_release_and_reproduction_use_distinct_exact_byte_signature_domains(
    signing_material: dict[str, Path],
    tmp_path: Path,
) -> None:
    """Ephemeral keys prove release approval and verifier evidence cannot be interchanged."""
    release = tmp_path / "release.yaml"
    release.write_text("human_approval:\n  operator_id: Chris\n", encoding="utf-8")
    statement = tmp_path / "reproduction.yaml"
    statement.write_text("evaluator_id: outside-1\n", encoding="utf-8")

    release_signature = sign_release_submission(release, signing_material["private_key"])
    statement_signature = sign_reproduction_statement(
        statement,
        signing_material["private_key"],
    )
    release_verification = verify_release_submission_signature(
        release,
        release_signature,
        signing_material["allowed_signers"],
        IDENTITY,
    )
    statement_verification = verify_reproduction_statement_signature(
        statement,
        statement_signature,
        signing_material["allowed_signers"],
        IDENTITY,
    )

    assert release_verification.namespace == RELEASE_SIGNATURE_NAMESPACE
    assert statement_verification.namespace == REPRODUCTION_SIGNATURE_NAMESPACE
    with pytest.raises(ProtocolSignatureError, match="verification failed"):
        verify_reproduction_statement_signature(
            release,
            release_signature,
            signing_material["allowed_signers"],
            IDENTITY,
        )

    statement.write_text("evaluator_id: changed\n", encoding="utf-8")
    with pytest.raises(ProtocolSignatureError, match="verification failed"):
        verify_reproduction_statement_signature(
            statement,
            statement_signature,
            signing_material["allowed_signers"],
            IDENTITY,
        )


def test_release_gate_consumes_verified_exact_submission_out_of_band(
    signing_material: dict[str, Path],
    tmp_path: Path,
) -> None:
    """A real ephemeral signature removes only the authorization blocker it proves."""
    submission_path = tmp_path / "candidate-submission.yaml"
    submission_path.write_bytes((ROOT / "benchmark" / "candidate-submission.yaml").read_bytes())
    signature = sign_release_submission(submission_path, signing_material["private_key"])

    submission, authorization = authorize_benchmark_submission(
        submission_path,
        signature,
        signing_material["allowed_signers"],
        IDENTITY,
    )
    gate = evaluate_benchmark_release(submission, authorization=authorization)
    codes = {issue.code for issue in gate.issues}

    assert gate.publishable is False
    assert PublicationIssueCode.RELEASE_AUTHORIZATION_MISSING not in codes
    assert PublicationIssueCode.CORPUS_SCENARIO_COUNT_INVALID in codes
