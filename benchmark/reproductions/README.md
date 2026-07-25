# Independent reproduction records

This directory may hold non-secret, evaluator-signed reproduction records after the
benchmark release gates are actually earned. It must never contain an active corpus,
escrow bundle, raw transcript, dummy-secret value, canary, machine-attestation contents,
private discrepancy review, or unaffiliated-attestation text.

Accepted records come only from this sequence:

1. sign exact reproduced `report.json` bytes with
   `stinger benchmark sign-reproduced-report`;
2. generate and resolve the private `reproduction-diff`;
3. run `build-reproduction-statement` against both verified bundle pairs;
4. have the unaffiliated evaluator sign the canonical statement; and
5. run `build-reproduction-record` to derive the existing release-schema record.

The statement builder writes its comparison manifest, discrepancy ledger, and unsigned
statement to a new access-controlled directory. Those private artifacts remain outside this
repository. The public record contains only evaluator/configuration identities and exact
statement, signature, and external-trust hashes.

Relocating or copying the target bundle is not independent reproduction evidence. The
builder requires distinct bundle paths, report bytes, and public/escrow manifests, plus a
distinct machine attestation. The reproduced report and final statement must use the same
evaluator identity, exact signing key, and external trust policy.

The machine hashes bind out-of-band identity attestations; they do not prove physical
hardware. Likewise, `release-check` verifies the evaluator's signed artifact bindings but
does not reopen escrow or independently rerun the private builder.
