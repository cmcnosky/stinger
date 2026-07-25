"""Detached OpenSSH signatures for benchmark governance artifacts.

The benchmark protocol is public evidence, so an HMAC or a hash beside the file is not
enough: either can be rewritten by the same actor who rewrites the protocol. This module
uses OpenSSH's Ed25519-capable ``ssh-keygen -Y sign`` format and an operator-maintained
``allowed_signers`` trust file. Stinger never generates, copies, or stores a private key.

Signing and verification are governance operations outside the deterministic scoring path.
They introduce no Python runtime dependency, but require an OpenSSH build with ``-Y``
signature support.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

PROTOCOL_SIGNATURE_NAMESPACE = "stinger-benchmark-protocol"
CANDIDATE_VALIDATION_SIGNATURE_NAMESPACE = "stinger-benchmark-candidate-validation"
CANDIDATE_PROMOTION_SIGNATURE_NAMESPACE = "stinger-benchmark-candidate-promotion"
CORPUS_FREEZE_SIGNATURE_NAMESPACE = "stinger-benchmark-corpus-freeze"
CONFORMANCE_SIGNATURE_NAMESPACE = "stinger-benchmark-conformance"
BASELINE_VERIFICATION_SIGNATURE_NAMESPACE = "stinger-benchmark-baseline-verification"
PILOT_EVIDENCE_SIGNATURE_NAMESPACE = "stinger-benchmark-pilot-evidence"
RELEASE_EVIDENCE_SIGNATURE_NAMESPACE = "stinger-benchmark-release-evidence"
RELEASE_SIGNATURE_NAMESPACE = "stinger-benchmark-release"
REPRODUCTION_SIGNATURE_NAMESPACE = "stinger-benchmark-reproduction"
REPRODUCED_REPORT_SIGNATURE_NAMESPACE = "stinger-benchmark-reproduced-report"
PUBLIC_REPRODUCTION_VERIFICATION_SIGNATURE_NAMESPACE = (
    "stinger-benchmark-public-reproduction-verification"
)
_KEY_FINGERPRINT_PATTERN = re.compile(rb"\bkey (SHA256:[A-Za-z0-9+/]+={0,2})(?:\s|$)")
_MAX_OPENSSH_OUTPUT_BYTES = 256 * 1024
_MAX_DIAGNOSTIC_BYTES = 4096
_OPENSSH_TIMEOUT_SECONDS = 60

__all__ = [
    "PROTOCOL_SIGNATURE_NAMESPACE",
    "CANDIDATE_VALIDATION_SIGNATURE_NAMESPACE",
    "CANDIDATE_PROMOTION_SIGNATURE_NAMESPACE",
    "CORPUS_FREEZE_SIGNATURE_NAMESPACE",
    "CONFORMANCE_SIGNATURE_NAMESPACE",
    "BASELINE_VERIFICATION_SIGNATURE_NAMESPACE",
    "PILOT_EVIDENCE_SIGNATURE_NAMESPACE",
    "RELEASE_EVIDENCE_SIGNATURE_NAMESPACE",
    "RELEASE_SIGNATURE_NAMESPACE",
    "REPRODUCTION_SIGNATURE_NAMESPACE",
    "REPRODUCED_REPORT_SIGNATURE_NAMESPACE",
    "PUBLIC_REPRODUCTION_VERIFICATION_SIGNATURE_NAMESPACE",
    "ArtifactSignatureVerification",
    "ProtocolSignatureError",
    "ProtocolSignatureVerification",
    "sign_release_submission",
    "sign_candidate_validation_receipt",
    "sign_candidate_promotion_statement",
    "sign_conformance_statement",
    "sign_baseline_verification_statement",
    "sign_pilot_evidence_statement",
    "sign_release_evidence_statement",
    "sign_corpus_freeze_statement",
    "sign_reproduced_report",
    "sign_reproduction_statement",
    "sign_public_reproduction_verification_statement",
    "sign_protocol",
    "verify_release_submission_signature",
    "verify_candidate_validation_receipt_signature",
    "verify_candidate_promotion_statement_signature",
    "verify_conformance_statement_signature",
    "verify_baseline_verification_statement_signature",
    "verify_pilot_evidence_statement_signature",
    "verify_release_evidence_statement_signature",
    "verify_corpus_freeze_statement_signature",
    "verify_reproduced_report_signature",
    "verify_reproduction_statement_signature",
    "verify_public_reproduction_verification_statement_signature",
    "verify_protocol_signature",
]


class ProtocolSignatureError(Exception):
    """Raised when protocol signing or verification cannot complete safely."""


@dataclass(frozen=True, slots=True)
class ProtocolSignatureVerification:
    """Identity and exact artifacts covered by a successful detached verification."""

    identity: str
    namespace: str
    protocol_sha256: str
    signature_sha256: str
    allowed_signers_sha256: str
    signing_key_fingerprint: str


@dataclass(frozen=True, slots=True)
class ArtifactSignatureVerification:
    """Identity and exact bytes covered by a non-protocol governance signature."""

    identity: str
    namespace: str
    artifact_sha256: str
    signature_sha256: str
    allowed_signers_sha256: str
    signing_key_fingerprint: str


def sign_protocol(
    protocol: Path,
    private_key: Path,
    *,
    namespace: str = PROTOCOL_SIGNATURE_NAMESPACE,
) -> Path:
    """Create ``<protocol>.sig`` with an existing operator-controlled SSH key.

    Args:
        protocol: Frozen protocol artifact to sign.
        private_key: Existing OpenSSH private key. It is passed to ``ssh-keygen`` and never
            read or copied by Stinger.
        namespace: Signature domain separator. The benchmark default is fixed.

    Returns:
        Path to the new detached ASCII-armored signature.

    Raises:
        ProtocolSignatureError: If inputs are ambiguous, OpenSSH is unavailable, a
            signature already exists, or signing fails.
    """
    return _sign_artifact(protocol, private_key, namespace=namespace, label="protocol")


def sign_release_submission(
    submission: Path,
    private_key: Path,
) -> Path:
    """Sign the exact release-submission bytes with the human-authorization namespace."""
    return _sign_artifact(
        submission,
        private_key,
        namespace=RELEASE_SIGNATURE_NAMESPACE,
        label="release submission",
    )


def sign_candidate_validation_receipt(
    receipt: Path,
    private_key: Path,
) -> Path:
    """Sign exact candidate-validation receipt bytes in their dedicated namespace."""
    return _sign_artifact(
        receipt,
        private_key,
        namespace=CANDIDATE_VALIDATION_SIGNATURE_NAMESPACE,
        label="candidate validation receipt",
    )


def sign_candidate_promotion_statement(
    statement: Path,
    private_key: Path,
) -> Path:
    """Sign an exact candidate-to-sealed transformation statement."""
    return _sign_artifact(
        statement,
        private_key,
        namespace=CANDIDATE_PROMOTION_SIGNATURE_NAMESPACE,
        label="candidate promotion statement",
    )


def sign_conformance_statement(
    statement: Path,
    private_key: Path,
) -> Path:
    """Sign exact conformance statement bytes in their dedicated namespace."""
    return _sign_artifact(
        statement,
        private_key,
        namespace=CONFORMANCE_SIGNATURE_NAMESPACE,
        label="conformance statement",
    )


def sign_baseline_verification_statement(
    statement: Path,
    private_key: Path,
) -> Path:
    """Sign exact artifact-derived baseline statement bytes."""
    return _sign_artifact(
        statement,
        private_key,
        namespace=BASELINE_VERIFICATION_SIGNATURE_NAMESPACE,
        label="baseline verification statement",
    )


def sign_pilot_evidence_statement(
    statement: Path,
    private_key: Path,
) -> Path:
    """Sign exact artifact-derived pilot evidence in its dedicated namespace."""
    return _sign_artifact(
        statement,
        private_key,
        namespace=PILOT_EVIDENCE_SIGNATURE_NAMESPACE,
        label="pilot evidence statement",
    )


def sign_release_evidence_statement(
    statement: Path,
    private_key: Path,
) -> Path:
    """Sign exact artifact-derived release evidence in its dedicated namespace."""
    return _sign_artifact(
        statement,
        private_key,
        namespace=RELEASE_EVIDENCE_SIGNATURE_NAMESPACE,
        label="release evidence statement",
    )


def sign_corpus_freeze_statement(
    statement: Path,
    private_key: Path,
) -> Path:
    """Sign exact corpus-freeze statement bytes in their dedicated namespace."""
    return _sign_artifact(
        statement,
        private_key,
        namespace=CORPUS_FREEZE_SIGNATURE_NAMESPACE,
        label="corpus freeze statement",
    )


def sign_reproduction_statement(
    statement: Path,
    private_key: Path,
) -> Path:
    """Sign an independent verifier statement that binds reproduction artifacts."""
    return _sign_artifact(
        statement,
        private_key,
        namespace=REPRODUCTION_SIGNATURE_NAMESPACE,
        label="reproduction statement",
    )


def sign_reproduced_report(
    report: Path,
    private_key: Path,
) -> Path:
    """Sign exact reproduced-report bytes with the evaluator-report namespace."""
    return _sign_artifact(
        report,
        private_key,
        namespace=REPRODUCED_REPORT_SIGNATURE_NAMESPACE,
        label="reproduced report",
    )


def sign_public_reproduction_verification_statement(
    statement: Path,
    private_key: Path,
) -> Path:
    """Sign an exact public-reproduction verification statement."""
    return _sign_artifact(
        statement,
        private_key,
        namespace=PUBLIC_REPRODUCTION_VERIFICATION_SIGNATURE_NAMESPACE,
        label="public reproduction verification statement",
    )


def verify_protocol_signature(
    protocol: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
    *,
    namespace: str = PROTOCOL_SIGNATURE_NAMESPACE,
) -> ProtocolSignatureVerification:
    """Verify a protocol against a detached signature and explicit signer trust policy.

    Args:
        protocol: Protocol bytes that were signed.
        signature: Detached OpenSSH signature.
        allowed_signers: OpenSSH allowed-signers file controlled by the verifier.
        identity: Expected signer identity from that file.
        namespace: Expected signature domain separator.

    Returns:
        Exact hashes and identity from the successful verification.

    Raises:
        ProtocolSignatureError: If any input is unsafe, trust is ambiguous, OpenSSH is
            unavailable, or signature verification fails.
    """
    protocol_bytes = _require_regular_file(protocol, "protocol")
    signature_bytes = _require_regular_file(signature, "protocol signature")
    signers_bytes = _require_regular_file(allowed_signers, "allowed signers")
    _validate_identity(identity)
    _validate_namespace(namespace)
    _ssh_keygen()

    completed = _run_verification(
        artifact_bytes=protocol_bytes,
        signature_bytes=signature_bytes,
        allowed_signers_bytes=signers_bytes,
        identity=identity,
        namespace=namespace,
    )
    if completed.returncode != 0:
        detail = _diagnostic(completed, "signature mismatch")
        raise ProtocolSignatureError(f"protocol signature verification failed: {detail}")

    return ProtocolSignatureVerification(
        identity=identity,
        namespace=namespace,
        protocol_sha256=_sha256(protocol_bytes),
        signature_sha256=_sha256(signature_bytes),
        allowed_signers_sha256=_sha256(signers_bytes),
        signing_key_fingerprint=_verified_key_fingerprint(completed),
    )


def verify_release_submission_signature(
    submission: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> ArtifactSignatureVerification:
    """Verify exact release-submission bytes against external signer trust."""
    return _verify_artifact_signature(
        submission,
        signature,
        allowed_signers,
        identity,
        namespace=RELEASE_SIGNATURE_NAMESPACE,
        label="release submission",
    )


def verify_candidate_validation_receipt_signature(
    receipt: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> ArtifactSignatureVerification:
    """Verify exact candidate-validation receipt bytes against external signer trust."""
    return _verify_artifact_signature(
        receipt,
        signature,
        allowed_signers,
        identity,
        namespace=CANDIDATE_VALIDATION_SIGNATURE_NAMESPACE,
        label="candidate validation receipt",
    )


def verify_candidate_promotion_statement_signature(
    statement: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> ArtifactSignatureVerification:
    """Verify an exact candidate-to-sealed statement against external trust."""
    return _verify_artifact_signature(
        statement,
        signature,
        allowed_signers,
        identity,
        namespace=CANDIDATE_PROMOTION_SIGNATURE_NAMESPACE,
        label="candidate promotion statement",
    )


def verify_conformance_statement_signature(
    statement: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> ArtifactSignatureVerification:
    """Verify exact conformance statement bytes against external signer trust."""
    return _verify_artifact_signature(
        statement,
        signature,
        allowed_signers,
        identity,
        namespace=CONFORMANCE_SIGNATURE_NAMESPACE,
        label="conformance statement",
    )


def verify_pilot_evidence_statement_signature(
    statement: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> ArtifactSignatureVerification:
    """Verify exact artifact-derived pilot evidence against external signer trust."""
    return _verify_artifact_signature(
        statement,
        signature,
        allowed_signers,
        identity,
        namespace=PILOT_EVIDENCE_SIGNATURE_NAMESPACE,
        label="pilot evidence statement",
    )


def verify_baseline_verification_statement_signature(
    statement: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> ArtifactSignatureVerification:
    """Verify exact baseline verification statement bytes against external trust."""
    return _verify_artifact_signature(
        statement,
        signature,
        allowed_signers,
        identity,
        namespace=BASELINE_VERIFICATION_SIGNATURE_NAMESPACE,
        label="baseline verification statement",
    )


def verify_release_evidence_statement_signature(
    statement: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> ArtifactSignatureVerification:
    """Verify exact release-evidence statement bytes against external trust."""
    return _verify_artifact_signature(
        statement,
        signature,
        allowed_signers,
        identity,
        namespace=RELEASE_EVIDENCE_SIGNATURE_NAMESPACE,
        label="release evidence statement",
    )


def verify_corpus_freeze_statement_signature(
    statement: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> ArtifactSignatureVerification:
    """Verify exact corpus-freeze statement bytes against external signer trust."""
    return _verify_artifact_signature(
        statement,
        signature,
        allowed_signers,
        identity,
        namespace=CORPUS_FREEZE_SIGNATURE_NAMESPACE,
        label="corpus freeze statement",
    )


def verify_reproduction_statement_signature(
    statement: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> ArtifactSignatureVerification:
    """Verify an independent reproduction statement and its external signer trust."""
    return _verify_artifact_signature(
        statement,
        signature,
        allowed_signers,
        identity,
        namespace=REPRODUCTION_SIGNATURE_NAMESPACE,
        label="reproduction statement",
    )


def verify_reproduced_report_signature(
    report: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> ArtifactSignatureVerification:
    """Verify exact reproduced-report bytes against the evaluator's external trust."""
    return _verify_artifact_signature(
        report,
        signature,
        allowed_signers,
        identity,
        namespace=REPRODUCED_REPORT_SIGNATURE_NAMESPACE,
        label="reproduced report",
    )


def verify_public_reproduction_verification_statement_signature(
    statement: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
) -> ArtifactSignatureVerification:
    """Verify an exact public-reproduction verification statement."""
    return _verify_artifact_signature(
        statement,
        signature,
        allowed_signers,
        identity,
        namespace=PUBLIC_REPRODUCTION_VERIFICATION_SIGNATURE_NAMESPACE,
        label="public reproduction verification statement",
    )


def _sign_artifact(
    artifact: Path,
    private_key: Path,
    *,
    namespace: str,
    label: str,
) -> Path:
    """Sign one immutable artifact snapshot without reading private-key bytes."""
    artifact_bytes = _require_regular_file(artifact, label)
    _require_regular_file(private_key, "private key")
    _validate_namespace(namespace)
    _ssh_keygen()

    signature = Path(f"{artifact}.sig")
    if signature.exists() or signature.is_symlink():
        raise ProtocolSignatureError(f"refusing to overwrite existing signature: {signature}")

    with tempfile.TemporaryDirectory(prefix="stinger-signature-create-") as temporary:
        snapshot = Path(temporary) / "artifact"
        snapshot.write_bytes(artifact_bytes)
        snapshot.chmod(0o600)
        completed = _run(
            [
                "ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(private_key),
                "-n",
                namespace,
                str(snapshot),
            ]
        )
        snapshot_signature = Path(f"{snapshot}.sig")
        if completed.returncode != 0:
            detail = _diagnostic(completed, "unknown OpenSSH error")
            raise ProtocolSignatureError(f"{label} signing failed: {detail}")
        signature_bytes = _require_regular_file(
            snapshot_signature,
            f"generated {label} signature",
        )
    if _require_regular_file(artifact, label) != artifact_bytes:
        raise ProtocolSignatureError(f"{label} changed while it was being signed")
    _create_signature_file(signature, signature_bytes)
    return signature


def _create_signature_file(destination: Path, content: bytes) -> None:
    """Publish a detached signature exactly once without a check/use overwrite race."""
    parent = destination.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ProtocolSignatureError("signature parent must be an existing real directory")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise ProtocolSignatureError(
                f"refusing to overwrite existing signature: {destination}"
            ) from exc
    finally:
        temporary.unlink(missing_ok=True)


def _verify_artifact_signature(
    artifact: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
    *,
    namespace: str,
    label: str,
) -> ArtifactSignatureVerification:
    """Verify one artifact with a fixed namespace and independently supplied trust file."""
    artifact_bytes = _require_regular_file(artifact, label)
    signature_bytes = _require_regular_file(signature, f"{label} signature")
    signers_bytes = _require_regular_file(allowed_signers, "allowed signers")
    _validate_identity(identity)
    _validate_namespace(namespace)
    _ssh_keygen()

    completed = _run_verification(
        artifact_bytes=artifact_bytes,
        signature_bytes=signature_bytes,
        allowed_signers_bytes=signers_bytes,
        identity=identity,
        namespace=namespace,
    )
    if completed.returncode != 0:
        detail = _diagnostic(completed, "signature mismatch")
        raise ProtocolSignatureError(f"{label} signature verification failed: {detail}")

    return ArtifactSignatureVerification(
        identity=identity,
        namespace=namespace,
        artifact_sha256=_sha256(artifact_bytes),
        signature_sha256=_sha256(signature_bytes),
        allowed_signers_sha256=_sha256(signers_bytes),
        signing_key_fingerprint=_verified_key_fingerprint(completed),
    )


def _run_verification(
    *,
    artifact_bytes: bytes,
    signature_bytes: bytes,
    allowed_signers_bytes: bytes,
    identity: str,
    namespace: str,
) -> subprocess.CompletedProcess[bytes]:
    """Run OpenSSH only against private snapshots of the already-hashed inputs."""
    with tempfile.TemporaryDirectory(prefix="stinger-signature-verify-") as temporary:
        root = Path(temporary)
        signature = root / "artifact.sig"
        allowed_signers = root / "allowed_signers"
        signature.write_bytes(signature_bytes)
        allowed_signers.write_bytes(allowed_signers_bytes)
        signature.chmod(0o600)
        allowed_signers.chmod(0o600)
        return _run(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(allowed_signers),
                "-I",
                identity,
                "-n",
                namespace,
                "-s",
                str(signature),
            ],
            stdin=artifact_bytes,
        )


def _run(argv: list[str], *, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    """Run the fixed OpenSSH client with a closed environment and bounded output."""
    if not argv or argv[0] != "ssh-keygen":
        raise ProtocolSignatureError("invalid protocol signature operation")
    executable = _ssh_keygen()
    command = [str(executable), *argv[1:]]
    try:
        completed = _run_ssh_keygen_process(
            command,
            input=stdin,
            env=_ssh_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProtocolSignatureError("could not execute protocol signature operation") from exc
    if (
        len(completed.stdout) > _MAX_OPENSSH_OUTPUT_BYTES
        or len(completed.stderr) > _MAX_OPENSSH_OUTPUT_BYTES
    ):
        raise ProtocolSignatureError("protocol signature operation produced excessive output")
    return completed


def _run_ssh_keygen_process(
    argv: list[str],
    *,
    input: bytes | None,
    env: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    """Launch the already-resolved OpenSSH client without a shell."""
    return subprocess.run(
        argv,
        input=input,
        stdin=subprocess.DEVNULL if input is None else None,
        capture_output=True,
        check=False,
        timeout=_OPENSSH_TIMEOUT_SECONDS,
        env=env,
    )


def _ssh_environment() -> dict[str, str]:
    """Return the entire environment supplied to OpenSSH.

    Constructing the mapping from scratch prevents caller-controlled ``PATH``, dynamic
    loader, askpass, shell-startup, Git, or locale variables from changing the verifier.
    """
    if os.name == "nt":
        return {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": r"C:\Windows\System32",
            "SYSTEMROOT": r"C:\Windows",
        }
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _diagnostic(completed: subprocess.CompletedProcess[bytes], fallback: str) -> str:
    """Decode OpenSSH diagnostics without letting locale bytes hide the real failure."""
    raw = completed.stderr.strip() or completed.stdout.strip()
    bounded = raw[:_MAX_DIAGNOSTIC_BYTES]
    return fallback if not bounded else bounded.decode("utf-8", errors="replace")


def _verified_key_fingerprint(completed: subprocess.CompletedProcess[bytes]) -> str:
    """Extract the exact public-key fingerprint OpenSSH says verified the signature.

    OpenSSH signatures carry the public key, and successful ``ssh-keygen -Y verify``
    diagnostics identify it as ``SHA256:<base64>``. Persisting that identity lets release
    governance distinguish two roles cryptographically instead of mistaking two signature
    namespaces for two independent signers.

    Args:
        completed: Successful ``ssh-keygen -Y verify`` result.

    Returns:
        The unique OpenSSH SHA-256 key fingerprint, including its ``SHA256:`` prefix.

    Raises:
        ProtocolSignatureError: If the verifier output does not identify exactly one key.
    """
    combined = b"\n".join((completed.stdout, completed.stderr))
    fingerprints: set[str] = {
        match.decode("ascii") for match in _KEY_FINGERPRINT_PATTERN.findall(combined)
    }
    if len(fingerprints) != 1:
        raise ProtocolSignatureError(
            "successful OpenSSH verification did not identify exactly one signing key"
        )
    return next(iter(fingerprints))


def _ssh_keygen() -> Path:
    """Resolve OpenSSH only from a fixed platform allowlist.

    Ambient ``PATH`` is deliberately irrelevant: a same-user executable must not be able
    to claim that an arbitrary governance artifact verified successfully.
    """
    candidates = (
        (Path(r"C:\Windows\System32\OpenSSH\ssh-keygen.exe"),)
        if os.name == "nt"
        else (Path("/usr/bin/ssh-keygen"),)
    )
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except OSError:
            continue
        if stat.S_ISREG(metadata.st_mode) and os.access(resolved, os.X_OK):
            return resolved
    raise ProtocolSignatureError(
        "a fixed system ssh-keygen with OpenSSH signature support is required"
    )


def _require_regular_file(path: Path, label: str) -> bytes:
    """Read a real regular file while rejecting symlink substitution."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProtocolSignatureError(f"{label} must be a real regular file: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ProtocolSignatureError(f"{label} must be a real regular file: {path}")
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
        raise ProtocolSignatureError(f"{label} must not be empty: {path}")
    return content


def _validate_identity(identity: str) -> None:
    """Keep signer identity a single unambiguous allowed-signers principal."""
    if not identity.strip() or identity != identity.strip() or any(c.isspace() for c in identity):
        raise ProtocolSignatureError(
            "signer identity must be one non-empty principal without whitespace"
        )


def _validate_namespace(namespace: str) -> None:
    """Require a stable single-token domain separator."""
    if not namespace or namespace != namespace.strip() or any(c.isspace() for c in namespace):
        raise ProtocolSignatureError(
            "signature namespace must be non-empty and contain no whitespace"
        )


def _sha256(content: bytes) -> str:
    """Return the lowercase sha256 digest of exact bytes."""
    return hashlib.sha256(content).hexdigest()
