"""Detached trust verification for the frozen benchmark protocol."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

import stinger.benchmark.signing as signing_module
from stinger.benchmark.gates import (
    PublicationIssueCode,
    authorize_benchmark_submission,
    evaluate_benchmark_release,
)
from stinger.benchmark.signing import (
    PILOT_EVIDENCE_SIGNATURE_NAMESPACE,
    PROTOCOL_SIGNATURE_NAMESPACE,
    RELEASE_SIGNATURE_NAMESPACE,
    REPRODUCED_REPORT_SIGNATURE_NAMESPACE,
    REPRODUCTION_SIGNATURE_NAMESPACE,
    ProtocolSignatureError,
    sign_pilot_evidence_statement,
    sign_protocol,
    sign_release_submission,
    sign_reproduced_report,
    sign_reproduction_statement,
    verify_pilot_evidence_statement_signature,
    verify_protocol_signature,
    verify_release_submission_signature,
    verify_reproduced_report_signature,
    verify_reproduction_statement_signature,
)
from stinger.cli import main

IDENTITY = "stinger-release@example.test"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def signing_material(tmp_path: Path) -> dict[str, Path]:
    """Generate an ephemeral Ed25519 key and separately supplied trust file."""
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
        "benchmark_protocol_version: 2.0.0\nbaseline_run_seed: 17\n",
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
        assert verification.signing_key_fingerprint.startswith("SHA256:")

    def test_tampered_protocol_and_wrong_identity_fail_closed(
        self, signing_material: dict[str, Path]
    ) -> None:
        signature = sign_protocol(
            signing_material["protocol"],
            signing_material["private_key"],
        )
        signing_material["protocol"].write_text(
            "benchmark_protocol_version: 2.0.0\nbaseline_run_seed: 18\n",
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

    def test_verification_uses_the_same_signature_and_trust_bytes_it_hashes(
        self,
        tmp_path: Path,
        signing_material: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Mutable caller paths cannot change what OpenSSH verifies after snapshotting."""
        signature = sign_protocol(
            signing_material["protocol"],
            signing_material["private_key"],
        )
        expected = verify_protocol_signature(
            signing_material["protocol"],
            signature,
            signing_material["allowed_signers"],
            IDENTITY,
        )

        alternate_key = tmp_path / "alternate-key"
        generated = subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(alternate_key),
            ],
            capture_output=True,
            check=False,
            text=True,
        )
        if generated.returncode != 0:
            pytest.fail(f"could not generate alternate test key: {generated.stderr}")
        alternate_artifact = tmp_path / "alternate-protocol.yaml"
        alternate_artifact.write_bytes(signing_material["protocol"].read_bytes())
        alternate_signature = sign_protocol(alternate_artifact, alternate_key)
        alternate_trust = (
            f"{IDENTITY} {alternate_key.with_suffix('.pub').read_text(encoding='utf-8').strip()}\n"
        ).encode()
        original_run = signing_module._run

        def replace_caller_paths_then_run(
            argv: list[str],
            *,
            stdin: bytes | None = None,
        ) -> subprocess.CompletedProcess[bytes]:
            signature.write_bytes(alternate_signature.read_bytes())
            signing_material["allowed_signers"].write_bytes(alternate_trust)
            return original_run(argv, stdin=stdin)

        monkeypatch.setattr(
            signing_module,
            "_run",
            replace_caller_paths_then_run,
        )

        verification = verify_protocol_signature(
            signing_material["protocol"],
            signature,
            signing_material["allowed_signers"],
            IDENTITY,
        )

        assert verification == expected

    def test_sign_and_verify_use_fixed_client_and_closed_environment(
        self,
        signing_material: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Both operations ignore ambient executable, loader, askpass, and Git controls."""
        hostile = {
            "PATH": "/attacker/bin",
            "LD_PRELOAD": "/attacker/lib.so",
            "DYLD_INSERT_LIBRARIES": "/attacker/lib.dylib",
            "SSH_ASKPASS": "/attacker/askpass",
            "GIT_DIR": "/attacker/git",
            "GIT_WORK_TREE": "/attacker/worktree",
            "BASH_ENV": "/attacker/bash-env",
            "ENV": "/attacker/shell-env",
        }
        for name, value in hostile.items():
            monkeypatch.setenv(name, value)

        observed: list[tuple[list[str], dict[str, str]]] = []
        original = signing_module._run_ssh_keygen_process

        def capture(
            argv: list[str],
            *,
            input: bytes | None,
            env: dict[str, str],
        ) -> subprocess.CompletedProcess[bytes]:
            observed.append((argv, env))
            return original(argv, input=input, env=env)

        monkeypatch.setattr(signing_module, "_run_ssh_keygen_process", capture)
        signature = sign_protocol(
            signing_material["protocol"],
            signing_material["private_key"],
        )
        verify_protocol_signature(
            signing_material["protocol"],
            signature,
            signing_material["allowed_signers"],
            IDENTITY,
        )

        assert len(observed) == 2
        assert all(Path(argv[0]).is_absolute() for argv, _env in observed)
        assert len({argv[0] for argv, _env in observed}) == 1
        for _argv, environment in observed:
            assert environment == signing_module._ssh_environment()
            assert environment["PATH"] != hostile["PATH"]
            assert (hostile.keys() - {"PATH"}).isdisjoint(environment)

    def test_path_shim_cannot_authorize_a_tampered_artifact(
        self,
        tmp_path: Path,
        signing_material: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A fake successful verifier on PATH is never executed."""
        signature = sign_protocol(
            signing_material["protocol"],
            signing_material["private_key"],
        )
        signing_material["protocol"].write_text(
            "benchmark_protocol_version: 2.0.0\nbaseline_run_seed: 999\n",
            encoding="utf-8",
        )
        shim_directory = tmp_path / "shim"
        shim_directory.mkdir()
        marker = tmp_path / "fake-verifier-ran"
        shim = shim_directory / "ssh-keygen"
        shim.write_text(
            "#!/bin/sh\n"
            f"printf ran > '{marker}'\n"
            "printf 'Good signature with ED25519 key SHA256:AAAAAAAAAAAAAAAAAAAA\\n'\n"
            "exit 0\n",
            encoding="utf-8",
        )
        shim.chmod(0o755)
        monkeypatch.setenv("PATH", str(shim_directory))
        monkeypatch.setenv("LD_PRELOAD", "/attacker/lib.so")
        monkeypatch.setenv("DYLD_INSERT_LIBRARIES", "/attacker/lib.dylib")
        monkeypatch.setenv("GIT_DIR", str(tmp_path / "attacker.git"))
        monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path / "attacker-tree"))
        monkeypatch.setenv("SSH_ASKPASS", str(tmp_path / "attacker-askpass"))

        with pytest.raises(ProtocolSignatureError, match="verification failed"):
            verify_protocol_signature(
                signing_material["protocol"],
                signature,
                signing_material["allowed_signers"],
                IDENTITY,
            )

        assert not marker.exists()

    def test_excessive_verifier_output_fails_closed(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """External diagnostics cannot become an unbounded memory or log channel."""

        def excessive(
            _argv: list[str],
            *,
            input: bytes | None,
            env: dict[str, str],
        ) -> subprocess.CompletedProcess[bytes]:
            del input, env
            return subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=b"x" * (signing_module._MAX_OPENSSH_OUTPUT_BYTES + 1),
                stderr=b"",
            )

        monkeypatch.setattr(signing_module, "_run_ssh_keygen_process", excessive)
        with pytest.raises(ProtocolSignatureError, match="excessive output"):
            signing_module._run(["ssh-keygen", "-Y", "verify"], stdin=b"artifact")


def test_signature_namespaces_are_distinct_while_the_signing_key_remains_visible(
    signing_material: dict[str, Path],
    tmp_path: Path,
) -> None:
    """Namespaces prevent artifact substitution but do not impersonate signer independence."""
    release = tmp_path / "release.yaml"
    release.write_text("release_authorization:\n  operator_id: Chris\n", encoding="utf-8")
    statement = tmp_path / "reproduction.yaml"
    statement.write_text("evaluator_id: cross-machine-role\n", encoding="utf-8")

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
    assert (
        release_verification.signing_key_fingerprint
        == statement_verification.signing_key_fingerprint
    )
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


class TestPilotEvidenceSigning:
    """Pilot evidence signatures have an exact, non-substitutable trust domain."""

    def test_signs_and_verifies_exact_pilot_evidence_bytes(
        self,
        signing_material: dict[str, Path],
        tmp_path: Path,
    ) -> None:
        statement = tmp_path / "pilot-evidence.json"
        statement.write_bytes(b'{"format_version":"2","scenario_count":120}\n')

        signature = sign_pilot_evidence_statement(
            statement,
            signing_material["private_key"],
        )
        verification = verify_pilot_evidence_statement_signature(
            statement,
            signature,
            signing_material["allowed_signers"],
            IDENTITY,
        )

        assert verification.identity == IDENTITY
        assert verification.namespace == PILOT_EVIDENCE_SIGNATURE_NAMESPACE
        assert verification.artifact_sha256
        assert verification.signature_sha256
        assert verification.allowed_signers_sha256
        assert verification.signing_key_fingerprint.startswith("SHA256:")
        assert PILOT_EVIDENCE_SIGNATURE_NAMESPACE not in {
            PROTOCOL_SIGNATURE_NAMESPACE,
            RELEASE_SIGNATURE_NAMESPACE,
            REPRODUCTION_SIGNATURE_NAMESPACE,
        }

    def test_pilot_signature_cannot_substitute_for_other_governance_namespaces(
        self,
        signing_material: dict[str, Path],
        tmp_path: Path,
    ) -> None:
        statement = tmp_path / "pilot-evidence.json"
        statement.write_bytes(b'{"format_version":"2","scenario_count":120}\n')
        signature = sign_pilot_evidence_statement(
            statement,
            signing_material["private_key"],
        )

        verifiers = (
            verify_protocol_signature,
            verify_release_submission_signature,
            verify_reproduction_statement_signature,
        )
        for verifier in verifiers:
            with pytest.raises(ProtocolSignatureError, match="verification failed"):
                verifier(
                    statement,
                    signature,
                    signing_material["allowed_signers"],
                    IDENTITY,
                )

    def test_other_governance_signature_cannot_substitute_for_pilot_evidence(
        self,
        signing_material: dict[str, Path],
        tmp_path: Path,
    ) -> None:
        artifacts_and_signers = (
            ("protocol.yaml", sign_protocol),
            ("release.json", sign_release_submission),
            ("reproduction.json", sign_reproduction_statement),
        )
        for filename, signer in artifacts_and_signers:
            artifact = tmp_path / filename
            artifact.write_bytes(b'{"artifact":"same bytes"}\n')
            signature = signer(artifact, signing_material["private_key"])

            with pytest.raises(ProtocolSignatureError, match="verification failed"):
                verify_pilot_evidence_statement_signature(
                    artifact,
                    signature,
                    signing_material["allowed_signers"],
                    IDENTITY,
                )


class TestReproducedReportSigning:
    """Evaluator report signatures bind exact bytes, identity, trust, and namespace."""

    def test_signs_and_verifies_exact_reproduced_report_bytes(
        self,
        signing_material: dict[str, Path],
        tmp_path: Path,
    ) -> None:
        report = tmp_path / "report.json"
        report.write_bytes(b'{"results":[],"rubric_version":"1.0.0"}\n')

        signature = sign_reproduced_report(report, signing_material["private_key"])
        verification = verify_reproduced_report_signature(
            report,
            signature,
            signing_material["allowed_signers"],
            IDENTITY,
        )

        assert verification.identity == IDENTITY
        assert verification.namespace == REPRODUCED_REPORT_SIGNATURE_NAMESPACE
        assert len(verification.artifact_sha256) == 64
        assert len(verification.signature_sha256) == 64
        assert len(verification.allowed_signers_sha256) == 64
        assert verification.signing_key_fingerprint.startswith("SHA256:")
        assert REPRODUCED_REPORT_SIGNATURE_NAMESPACE not in {
            PROTOCOL_SIGNATURE_NAMESPACE,
            RELEASE_SIGNATURE_NAMESPACE,
            REPRODUCTION_SIGNATURE_NAMESPACE,
        }

    def test_report_signature_cannot_substitute_for_statement_or_other_namespaces(
        self,
        signing_material: dict[str, Path],
        tmp_path: Path,
    ) -> None:
        report = tmp_path / "report.json"
        report.write_bytes(b'{"results":[]}\n')
        statement = tmp_path / "statement.json"
        statement.write_bytes(b'{"evaluator_id":"cross-machine-role"}\n')
        report_signature = sign_reproduced_report(
            report,
            signing_material["private_key"],
        )
        statement_signature = sign_reproduction_statement(
            statement,
            signing_material["private_key"],
        )

        with pytest.raises(ProtocolSignatureError, match="verification failed"):
            verify_reproduction_statement_signature(
                report,
                report_signature,
                signing_material["allowed_signers"],
                IDENTITY,
            )
        with pytest.raises(ProtocolSignatureError, match="verification failed"):
            verify_reproduced_report_signature(
                statement,
                statement_signature,
                signing_material["allowed_signers"],
                IDENTITY,
            )
        with pytest.raises(ProtocolSignatureError, match="verification failed"):
            verify_protocol_signature(
                report,
                report_signature,
                signing_material["allowed_signers"],
                IDENTITY,
            )

    def test_tampering_wrong_identity_and_wrong_trust_fail_closed(
        self,
        signing_material: dict[str, Path],
        tmp_path: Path,
    ) -> None:
        report = tmp_path / "report.json"
        original_bytes = b'{"results":[]}\n'
        report.write_bytes(original_bytes)
        signature = sign_reproduced_report(report, signing_material["private_key"])

        report.write_bytes(b'{"results":[{"outcome":"honest"}]}\n')
        with pytest.raises(ProtocolSignatureError, match="verification failed"):
            verify_reproduced_report_signature(
                report,
                signature,
                signing_material["allowed_signers"],
                IDENTITY,
            )
        report.write_bytes(original_bytes)

        with pytest.raises(ProtocolSignatureError, match="verification failed"):
            verify_reproduced_report_signature(
                report,
                signature,
                signing_material["allowed_signers"],
                "another@example.test",
            )

        alternate_key = tmp_path / "alternate-key"
        generated = subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(alternate_key),
            ],
            capture_output=True,
            check=False,
            text=True,
        )
        if generated.returncode != 0:
            pytest.fail(f"could not generate alternate test key: {generated.stderr}")
        wrong_trust = tmp_path / "wrong-allowed-signers"
        alternate_public_key = alternate_key.with_suffix(".pub").read_text(encoding="utf-8")
        wrong_trust.write_text(f"{IDENTITY} {alternate_public_key}", encoding="utf-8")

        with pytest.raises(ProtocolSignatureError, match="verification failed"):
            verify_reproduced_report_signature(
                report,
                signature,
                wrong_trust,
                IDENTITY,
            )

        wrong_key_report = tmp_path / "wrong-key-report.json"
        wrong_key_report.write_bytes(original_bytes)
        wrong_key_signature = sign_reproduced_report(wrong_key_report, alternate_key)
        with pytest.raises(ProtocolSignatureError, match="verification failed"):
            verify_reproduced_report_signature(
                wrong_key_report,
                wrong_key_signature,
                signing_material["allowed_signers"],
                IDENTITY,
            )

    def test_rejects_unsafe_or_ambiguous_inputs(
        self,
        signing_material: dict[str, Path],
        tmp_path: Path,
    ) -> None:
        report = tmp_path / "report.json"
        report.write_bytes(b'{"results":[]}\n')
        signature = sign_reproduced_report(report, signing_material["private_key"])

        linked_report = tmp_path / "linked-report.json"
        linked_report.symlink_to(report)
        with pytest.raises(ProtocolSignatureError, match="real regular file"):
            sign_reproduced_report(
                linked_report,
                signing_material["private_key"],
            )
        with pytest.raises(ProtocolSignatureError, match="real regular file"):
            verify_reproduced_report_signature(
                linked_report,
                signature,
                signing_material["allowed_signers"],
                IDENTITY,
            )
        with pytest.raises(ProtocolSignatureError, match="identity"):
            verify_reproduced_report_signature(
                report,
                signature,
                signing_material["allowed_signers"],
                " evaluator@example.test ",
            )
        with pytest.raises(ProtocolSignatureError, match="overwrite"):
            sign_reproduced_report(report, signing_material["private_key"])

    def test_verification_uses_exact_snapshotted_report_signature_and_trust_bytes(
        self,
        signing_material: dict[str, Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Caller paths cannot change what OpenSSH verifies after snapshotting."""
        report = tmp_path / "report.json"
        report.write_bytes(b'{"results":[]}\n')
        signature = sign_reproduced_report(report, signing_material["private_key"])
        expected = verify_reproduced_report_signature(
            report,
            signature,
            signing_material["allowed_signers"],
            IDENTITY,
        )

        alternate_key = tmp_path / "alternate-key"
        generated = subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(alternate_key),
            ],
            capture_output=True,
            check=False,
            text=True,
        )
        if generated.returncode != 0:
            pytest.fail(f"could not generate alternate test key: {generated.stderr}")
        alternate_report = tmp_path / "alternate-report.json"
        alternate_report.write_bytes(b'{"results":[{"outcome":"cheated"}]}\n')
        alternate_signature = sign_reproduced_report(alternate_report, alternate_key)
        alternate_trust = (
            f"{IDENTITY} {alternate_key.with_suffix('.pub').read_text(encoding='utf-8').strip()}\n"
        ).encode()
        original_run = signing_module._run

        def replace_caller_paths_then_run(
            argv: list[str],
            *,
            stdin: bytes | None = None,
        ) -> subprocess.CompletedProcess[bytes]:
            report.write_bytes(alternate_report.read_bytes())
            signature.write_bytes(alternate_signature.read_bytes())
            signing_material["allowed_signers"].write_bytes(alternate_trust)
            return original_run(argv, stdin=stdin)

        monkeypatch.setattr(
            signing_module,
            "_run",
            replace_caller_paths_then_run,
        )

        verification = verify_reproduced_report_signature(
            report,
            signature,
            signing_material["allowed_signers"],
            IDENTITY,
        )

        assert verification == expected

    def test_signing_uses_a_snapshot_and_refuses_a_caller_path_swap(
        self,
        signing_material: dict[str, Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A report swapped while OpenSSH runs cannot receive a misleading signature."""
        report = tmp_path / "report.json"
        report.write_bytes(b'{"results":[]}\n')
        original_run = signing_module._run

        def replace_report_then_run(
            argv: list[str],
            *,
            stdin: bytes | None = None,
        ) -> subprocess.CompletedProcess[bytes]:
            report.write_bytes(b'{"results":[{"outcome":"cheated"}]}\n')
            return original_run(argv, stdin=stdin)

        monkeypatch.setattr(signing_module, "_run", replace_report_then_run)

        with pytest.raises(ProtocolSignatureError, match="changed while it was being signed"):
            sign_reproduced_report(report, signing_material["private_key"])

        assert not Path(f"{report}.sig").exists()


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
