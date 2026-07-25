# Machine-environment attestation claim boundary

`stinger.benchmark.machine_environment` replaces an arbitrary operator-authored machine
identity file with two separate artifacts:

1. A canonical, stable identity artifact derived locally from macOS
   `IOPlatformUUID`, Linux `machine-id`, or Windows `MachineGuid`. The raw operating-system
   value is never written. Stinger emits only an application-scoped SHA-256 commitment plus
   the observed platform and execution architecture.
2. A canonical workflow attestation that binds that identity artifact to exact workflow
   input and receipt hashes, an exact clean Stinger commit, the Python runtime, and a signer
   identity. A detached OpenSSH signature uses the dedicated
   `stinger-benchmark-machine-workflow` namespace and an externally supplied trust policy.

The identity artifact intentionally excludes workflow-specific fields. Its exact SHA-256
therefore remains stable when the same environment runs multiple workflows, so changing a
receipt cannot manufacture a new machine fingerprint.

## What the mechanical path establishes

- local construction refuses to proceed unless it can read one unambiguous supported
  operating-system identity source and re-observe the same identity around workflow
  binding;
- its raw identifier was reduced to a Stinger-specific commitment;
- external verification proves that the platform, architecture, clean commit, workflow
  input, and workflow receipt recorded in the attestation were bound together; and
- external verification proves that the trusted OpenSSH key signed those exact attestation
  bytes.

## What it does not prove

It is not TPM, Secure Enclave, cloud-provider, or physical-hardware attestation. A cloned
virtual-machine image can carry a cloned `machine-id`; a privileged operator can replace an
operating-system identity source; and a signature establishes signer accountability, not
organizational independence or truthfulness. Linux container namespaces are rejected
when recognized because their machine identity is not a trustworthy stable host
discriminator; absence of a recognized marker is not remote proof that no container exists.
The application-scoped commitment is intentionally linkable across Stinger workflows on
the same environment, although it does not expose the raw operating-system identifier.

Accordingly, public wording may say **host-derived, separately signed, distinct-environment
evidence**. It must not say **hardware-proven**, **TPM-attested**, or **operator-independent**
unless a later protocol adds and verifies an appropriate external attestation service.

Artifact construction and same-host conformance must parse and locally verify the identity;
merely hashing an arbitrary file remains insufficient. A later baseline or reproduction
auditor usually runs on a different host and therefore must not compare the recorded
identity with its own machine. It instead verifies the signed workflow attestation against
the exact input, receipt, commit, signer identity, signature namespace, and external
allowed-signers policy.
