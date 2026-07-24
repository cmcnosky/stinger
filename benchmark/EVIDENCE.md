# Benchmark evidence operations

These commands operate only after a candidate baseline and sealed corpus exist. They do not
grant release eligibility.

## Protocol trust

Chris supplies an existing release-signing key stored outside this repository:

```bash
stinger benchmark sign-protocol benchmark/protocol.yaml \
  --private-key /access-controlled/path/release-key

stinger benchmark verify-protocol benchmark/protocol.yaml \
  --signature benchmark/protocol.yaml.sig \
  --allowed-signers /independently-obtained/path/allowed_signers \
  --signer-identity stinger-release@example.org
```

Stinger never generates or copies the private key. A verifier obtains the public
`allowed_signers` policy independently; trusting only the copy delivered inside a bundle
would be circular.

## Release and reproduction authority

Protocol signing freezes the rules; it does not authorize publication. After every
evidence field is final, Chris signs the exact release submission:

```bash
stinger benchmark sign-release /access-controlled/path/release-submission.yaml \
  --private-key /access-controlled/path/release-key
```

The unaffiliated evaluator independently creates and signs the exact reproduction
statement. Its schema is `IndependentReproductionStatement` in
`stinger benchmark release-schema`; it binds the target and reproduced reports,
configuration identities, public/escrow manifests, separate-machine fingerprints, and
discrepancy ledger.

```bash
stinger benchmark sign-reproduction /verifier/path/reproduction-statement.yaml \
  --private-key /verifier/path/verifier-key
```

The final gate verifies both signatures against independently obtained signer policies:

```bash
stinger benchmark release-check /access-controlled/path/release-submission.yaml \
  --signature /access-controlled/path/release-submission.yaml.sig \
  --allowed-signers /independently-obtained/path/release_allowed_signers \
  --signer-identity stinger-release@example.org \
  --reproduction-statement /verifier/path/reproduction-statement.yaml \
  --reproduction-signature /verifier/path/reproduction-statement.yaml.sig \
  --verifier-allowed-signers /independently-obtained/path/verifier_allowed_signers \
  --verifier-identity independent-verifier@example.org
```

The release signature uses a namespace distinct from protocol signatures. The verifier
statement uses a third namespace and cannot be substituted for Chris's release authority.
Namespaces prevent cross-artifact substitution but do not prove that two people signed:
the final gate also requires different signer identities, different verified signing-key
fingerprints, and different signer-policy files for the release and reproduction roles.

## Public bundle

`bundle-public` accepts protocol/config/report artifacts plus an explicit allowlist of
publishable logs. It requires:

- the detached protocol signature and signer policy;
- at least one active sealed source for exact-file comparison; and
- marker files containing every active canary and dummy-secret value.

Marker values are read from files so they do not appear in process arguments. The command
rejects exact sealed files, canary/secret substrings, sensitive path roles, private-key
material, symlinks, extra files, and any hash/size/mode mismatch. Verification requires the
same leakage policy and independently trusted signer policy again.

Run `stinger benchmark bundle-public --help` for the complete argument list.

## Escrow bundle

`bundle-escrow` copies the full sealed corpus and rerunnable evidence, verifies its exact
inventory, and embeds a conspicuous warning. It is **not encrypted**. Create it only in an
access-controlled destination and transfer it through a channel approved for active
benchmark material.

Run `stinger benchmark bundle-escrow --help` for the complete argument list.

The resulting public and escrow manifest hashes are referenced by the accepted baseline
record. A successful bundle check is necessary but does not replace corpus reviews,
outside reproduction, or human release approval.

## Artifact-derived baseline records

Accepted baseline records are constructed with the verifier-side builder, never by
hand-entering hashes or favorable booleans:

```bash
stinger benchmark build-baseline-record \
  --configuration-id pinned-configuration-id \
  --corpus-record /access-controlled/path/sealed-corpus-record.json \
  --public-bundle /verified/path/public-bundle \
  --escrow-bundle /access-controlled/path/escrow-bundle \
  --forbidden-source /access-controlled/path/active-sealed-corpus \
  --marker-file /access-controlled/path/canary-value \
  --marker-file /access-controlled/path/dummy-secret-value \
  --allowed-signers /independently-obtained/path/allowed_signers \
  --signer-identity stinger-release@example.org \
  --machine-identity /verifier/path/machine-identity-attestation \
  --output /new/path/baseline-record.json
```

The command re-verifies both bundles under independently obtained protocol trust, proves
that the public leakage comparison set covers the paired escrow corpus, snapshots the
verified core bytes, makes OpenSSH consume private snapshots of the exact signature and
trust-policy bytes being hashed, and cross-binds the protocol, signature, trust policy, report,
configuration fingerprint, corpus, and benchmark metadata. It then re-scores the report,
checks publication pins, Docker isolation configuration and observed image/invocation
provenance, recomputes deterministic blocked order, validates any error dispositions, and
runs the release gate's exact per-configuration evaluator.

`report_sha256` is the canonical typed-report hash. The two bundle hashes are SHA-256 over
the exact verified `bundle.manifest.json` bytes, not the manifest's internal inventory
hash. The builder creates canonical JSON at a new path and never copies or prints escrow
contents. It also rejects a derived record that repeats any private corpus, escrow, trust,
or machine-attestation input path, active canary, or dummy-secret marker.

The machine-identity input is an out-of-band operator attestation. Binding its exact bytes
detects disagreement between records, but does not prove physical hardware identity.
Likewise, the derived `contained` field means the verified resolved configuration required
Docker and the stored runtime provenance matched the pinned agent and verification images;
it is not independent hardware telemetry for every process. These trust boundaries remain
visible rather than being upgraded into claims the artifacts cannot prove.

The public `release-check` interface does not use the active corpus, escrow bundle, marker
files, or leakage policy. It consumes the already-derived record inside the signed release
submission.
