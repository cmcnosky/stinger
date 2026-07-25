# Cross-machine reproduction records

This directory may hold non-secret, signed reproduction records only after the release
gates are earned. It must never contain an active corpus, escrow bundle, raw transcript,
dummy-secret value, canary, machine-identity contents, or private bundle path.

Accepted records come only from this machine-derived sequence:

1. sign the exact reproduced `report.json` bytes with
   `stinger benchmark sign-reproduced-report`;
2. generate the automatic `reproduction-diff`;
3. run `build-reproduction-statement` against both verified bundle pairs;
4. sign the canonical statement under the reproduction namespace; and
5. run `build-reproduction-record` to derive the release-schema record.

The statement builder writes a comparison manifest, discrepancy ledger, and unsigned
statement to a new access-controlled directory. The public record contains only
configuration and signer-role identities plus exact statement, signature, and trust-policy
hashes.

Target and reproduced reports must have identical scenario/family sets, repetition
indices, sealed split, scenario versions, cluster identities, protocol, corpus,
configuration, and agent fingerprints. Their modal outcomes must match exactly.
Classification-relevant per-run differences receive deterministic IDs and the sole fixed
classification `expected_agent_variance_modal_stable`; the ledger is not editable.

Relocating or copying target evidence is not cross-machine reproduction. The builder
requires distinct bundle paths, report bytes, public/escrow manifests, host-derived
environment commitments, and signed workflow attestations. The reproduced report and final
statement use the same reproduction-role identity, signing key, and separately supplied
trust policy.

Machine hashes bind privacy-preserving operating-system identity commitments; they do not
prove TPM or physical hardware identity, cloud-provider origin, organizational
independence, or anti-cloning. Likewise, `release-check` verifies the signed artifact
bindings but does not reopen escrow or rerun the private builder.
