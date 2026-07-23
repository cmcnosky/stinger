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
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

PROTOCOL_SIGNATURE_NAMESPACE = "stinger-benchmark-protocol"
RELEASE_SIGNATURE_NAMESPACE = "stinger-benchmark-release"
REPRODUCTION_SIGNATURE_NAMESPACE = "stinger-benchmark-reproduction"

__all__ = [
    "PROTOCOL_SIGNATURE_NAMESPACE",
    "RELEASE_SIGNATURE_NAMESPACE",
    "REPRODUCTION_SIGNATURE_NAMESPACE",
    "ArtifactSignatureVerification",
    "ProtocolSignatureError",
    "ProtocolSignatureVerification",
    "sign_release_submission",
    "sign_reproduction_statement",
    "sign_protocol",
    "verify_release_submission_signature",
    "verify_reproduction_statement_signature",
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


@dataclass(frozen=True, slots=True)
class ArtifactSignatureVerification:
    """Identity and exact bytes covered by a non-protocol governance signature."""

    identity: str
    namespace: str
    artifact_sha256: str
    signature_sha256: str
    allowed_signers_sha256: str


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

    completed = _run(
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
        stdin=protocol_bytes,
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


def _sign_artifact(
    artifact: Path,
    private_key: Path,
    *,
    namespace: str,
    label: str,
) -> Path:
    """Sign one existing governance artifact without reading private-key bytes."""
    _require_regular_file(artifact, label)
    _require_regular_file(private_key, "private key")
    _validate_namespace(namespace)
    _ssh_keygen()

    signature = Path(f"{artifact}.sig")
    if signature.exists() or signature.is_symlink():
        raise ProtocolSignatureError(f"refusing to overwrite existing signature: {signature}")

    completed = _run(
        [
            "ssh-keygen",
            "-Y",
            "sign",
            "-f",
            str(private_key),
            "-n",
            namespace,
            str(artifact),
        ]
    )
    if completed.returncode != 0:
        if signature.is_file() and not signature.is_symlink():
            signature.unlink()
        detail = _diagnostic(completed, "unknown OpenSSH error")
        raise ProtocolSignatureError(f"{label} signing failed: {detail}")
    _require_regular_file(signature, f"generated {label} signature")
    return signature


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

    completed = _run(
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
    if completed.returncode != 0:
        detail = _diagnostic(completed, "signature mismatch")
        raise ProtocolSignatureError(f"{label} signature verification failed: {detail}")

    return ArtifactSignatureVerification(
        identity=identity,
        namespace=namespace,
        artifact_sha256=_sha256(artifact_bytes),
        signature_sha256=_sha256(signature_bytes),
        allowed_signers_sha256=_sha256(signers_bytes),
    )


def _run(argv: list[str], *, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    """Run OpenSSH without a shell and capture bounded text diagnostics."""
    try:
        return subprocess.run(
            argv,
            input=stdin,
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProtocolSignatureError(
            f"could not execute protocol signature operation: {exc}"
        ) from exc


def _diagnostic(completed: subprocess.CompletedProcess[bytes], fallback: str) -> str:
    """Decode OpenSSH diagnostics without letting locale bytes hide the real failure."""
    raw = completed.stderr.strip() or completed.stdout.strip()
    return fallback if not raw else raw.decode("utf-8", errors="replace")


def _ssh_keygen() -> None:
    """Require the external verifier explicitly rather than failing mid-operation."""
    if shutil.which("ssh-keygen") is None:
        raise ProtocolSignatureError(
            "ssh-keygen with OpenSSH signature support is required for benchmark protocols"
        )


def _require_regular_file(path: Path, label: str) -> bytes:
    """Read a real regular file while rejecting symlink substitution."""
    if path.is_symlink() or not path.is_file():
        raise ProtocolSignatureError(f"{label} must be a real regular file: {path}")
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise ProtocolSignatureError(f"{label} is not readable: {path}: {exc}") from exc
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
