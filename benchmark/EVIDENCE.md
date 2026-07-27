# Benchmark Protocol 2 evidence operations

These commands operate only after candidate construction exists. They do not grant release
eligibility, change the frozen score, or turn the public 30-scenario suite into headline
benchmark evidence.

> **Credential-isolation mechanism implemented; no sealed run claimed:** Protocol 2 rejects
> ordinary direct credential forwarding and `credential_mount`. Its closed Codex/OpenAI and
> Claude Code/Anthropic paths place the raw credential only in an external broker container;
> the untrusted agent receives an opaque per-invocation lease on a fresh Docker-internal
> network. Codex routing is the signed `openai_base_url` CLI override, never
> `OPENAI_BASE_URL`; Claude Code routing is `ANTHROPIC_BASE_URL`. Policy, broker
> configuration, exact destination and empty file/mount projection, broker source/image,
> both fresh network identities, and Docker runtime are mechanically bound. The agent runs on an isolated IPv4 bridge with
> no host gateway or IPv6, resolves only the broker alias through Docker's embedded DNS with
> loopback-only upstream resolution, and has inherited image healthchecks disabled. The broker
> reaches its fixed provider only through a fresh user-defined IPv4 NAT bridge containing no
> unrelated container. Before
> launch, Stinger rejects raw, hex, standard or URL-safe Base64, and percent-encoded credential
> forms in the final argv, workdir paths/links/files, image metadata, or exported final rootfs;
> signed prohibited credential-path suffixes and a nonempty agent config home also fail
> closed.
> Exact loaded configuration bytes, effective destination/test-mode readiness, bounded
> connection lifetime/concurrency, per-invocation identities/audit, and cleanup of both
> networks are evidence-bound. Tests use only synthetic
> credentials and local fake providers. No live provider or sealed review, QA, blind solve,
> pilot, baseline, or reproduction has been run or is claimed.

> **Agent-image supply-chain HOLD:** The signed Protocol 2 verification-image policy binds
> only the exact network-disabled verifier Dockerfile, hashed dependency lock, platform, and
> immutable image ID; the broker reuses a protocol-approved immutable image to execute its
> separately source-bound server. This does not approve the networked agent images that
> execute sealed prompts. Do not run live sealed work until those agent bytes have their own
> signed, mechanically verified source/attestation policy. The six-configuration baseline
> also requires three providers, but only two broker routes are defined today; a third route
> requires a newly signed policy. The verifier policy proves an observation through the
> bounded Docker daemon/admin boundary, not reproducible build provenance.

## Protocol trust

Chris supplies an existing signing key stored outside this repository:

```bash
stinger benchmark sign-protocol benchmark/protocol.yaml \
  --private-key /access-controlled/path/release-key

stinger benchmark verify-protocol benchmark/protocol.yaml \
  --signature benchmark/protocol.yaml.sig \
  --allowed-signers /separately-supplied/path/protocol_allowed_signers \
  --signer-identity stinger-release@example.org
```

Stinger never generates or copies the private key. Verification uses a separately supplied
`allowed_signers` policy; a trust file is not accepted merely because it arrived inside a
bundle.

## Candidate validation receipt

Before changing the candidate corpus into a sealed scoring corpus, build one public,
aggregate receipt from the exact private candidate tree:

```bash
stinger benchmark build-candidate-receipt \
  --candidate-root /access-controlled/path/real-candidate-corpus \
  --metadata /access-controlled/path/candidate-validation-metadata.json \
  --canary-registry /access-controlled/path/canary-registry.json \
  --access-ledger /access-controlled/path/access-ledger.jsonl \
  --repository /clean/path/stinger \
  --verification-image stinger-runner:1 \
  --signer-identity candidate-validation@example.org \
  --output /new/public/path/candidate-validation-receipt.json

stinger benchmark sign-candidate-receipt \
  /new/public/path/candidate-validation-receipt.json \
  --private-key /access-controlled/path/candidate-validation-key

stinger benchmark verify-candidate-receipt \
  /new/public/path/candidate-validation-receipt.json \
  --signature /new/public/path/candidate-validation-receipt.json.sig \
  --allowed-signers /separately-supplied/path/candidate_allowed_signers \
  --signer-identity candidate-validation@example.org
```

The builder rejects a symlinked candidate root, snapshots bounded regular files without
following links, requires a clean and stable Stinger commit, verifies the complete tracked
Stinger implementation roots, pins an inspected immutable Docker image ID, and runs the
validity contract for all 120 candidates in the canonical Docker sandbox. The public API
has no caller-supplied sandbox factory. Docker is resolved only from fixed platform paths
under a sanitized environment; the receipt binds the exact client-binary hash and a
bounded local-context/server runtime fingerprint, both of which are re-observed before
finalization. It derives family/size counts, unique-cluster count, canary coverage,
identity and validation inventories, and the cooperative access-ledger root.
Repository-size strata are explicit private metadata declarations that the receipt binds;
Stinger does not claim they were inferred by an objective size classifier.

The resulting canonical JSON contains only aggregate counts, version/build/image pins, and
content hashes. It contains no scenario identifiers, prompts, titles, cluster labels,
canary values, or private paths. Its access-log hash chain is explicitly cooperative—not
kernel-enforced or independently anchored. The detached signature uses
`stinger-benchmark-candidate-validation`.

The current public package is committed at
[`benchmark/receipts/candidate-validation-v2/`](receipts/candidate-validation-v2/).
It verifies 120 machine-validated benchmark-candidate scenarios: 24 per family, with eight
small, eight medium, and eight larger multi-module repositories per family. It binds
Stinger merge commit `d34cc05af95c697d327de67dfe1162f6a3f1d2ae`, Protocol `2.0.0`,
rubric `1.0.0`, the approved verifier identity, 120 unique clusters, 120 canaries, and
120/120 contained validity results. Verify the committed bytes without access to the
private candidate:

```bash
(cd benchmark/receipts/candidate-validation-v2 && shasum -a 256 -c SHA256SUMS)

stinger benchmark verify-candidate-receipt \
  benchmark/receipts/candidate-validation-v2/candidate-validation-receipt.json \
  --signature \
    benchmark/receipts/candidate-validation-v2/candidate-validation-receipt.json.sig \
  --allowed-signers \
    benchmark/receipts/candidate-validation-v2/candidate-validation.allowed_signers \
  --signer-identity stinger-candidate-validation-v2
```

This receipt is candidate-validation evidence only. It is not a Protocol 2 construction
receipt, accepted machine-review or QA evidence, a frozen or sealed scoring corpus, a
baseline result, a cross-machine reproduction, or a benchmark release.

## Candidate promotion

Promotion is the only permitted candidate-to-sealed mutation: it changes exactly the
`benchmark_split` lifecycle field from `candidate` to `sealed`, revalidates the promoted
tree, and atomically creates a new private package. It does not freeze the corpus or
authorize baseline execution.

```bash
stinger benchmark promote-candidate-corpus \
  --candidate-root /access-controlled/path/real-candidate-corpus \
  --metadata /access-controlled/path/candidate-validation-metadata.json \
  --canary-registry /access-controlled/path/canary-registry.json \
  --access-ledger /access-controlled/path/access-ledger.jsonl \
  --candidate-receipt /new/public/path/candidate-validation-receipt.json \
  --candidate-receipt-signature /new/public/path/candidate-validation-receipt.json.sig \
  --candidate-allowed-signers /separately-supplied/path/candidate_allowed_signers \
  --candidate-signer-identity candidate-validation@example.org \
  --repository /clean/path/stinger \
  --verification-image stinger-runner:1 \
  --promotion-signer-identity candidate-promotion@example.org \
  --output /new/access-controlled/path/promoted-corpus-package

stinger benchmark sign-candidate-promotion \
  /new/access-controlled/path/promoted-corpus-package/candidate-promotion-statement.json \
  --private-key /access-controlled/path/candidate-promotion-key
```

The complete package contains the promoted `corpus/`, the extended cooperative access
ledger, and `candidate-promotion-statement.json`. Keep the package private. The statement
is path-free, binds its own fixed-client Docker runtime fingerprint, and uses the
`stinger-benchmark-candidate-promotion` namespace. The fingerprint is local observation,
not TPM or administrator-integrity proof; a privileged machine administrator remains
capable of replacing or emulating the local daemon.

## Artifact-derived corpus construction receipt

The construction builder consumes the promoted `corpus/` plus exact custody, canary,
access-ledger, provenance, containment, dummy-safety, honest/cheat variant, verified QA,
machine-review, and selected blind-solve artifacts for all 120 scenarios. It re-verifies
those private artifacts and derives the complete unfrozen `SealedCorpusRecord`; callers do
not hand-enter that record.

Put the complete path-bearing inputs in the closed private
`CorpusConstructionInputManifest` schema, then run:

```bash
stinger benchmark build-corpus-construction-receipt \
  --input-manifest /access-controlled/path/corpus-construction-inputs.yaml \
  --output /new/access-controlled/path/corpus-construction-receipt.json
```

The command reopens and snapshots every declared artifact, runs the fixed construction
workflow, and writes the canonical path-free receipt to a new file. Unknown fields,
missing coverage, substituted implementation code, noncanonical JSON inputs, and changed
inputs fail closed. Do not serialize a caller-built `SealedCorpusRecord`; downstream pilot
and freeze commands consume the already-derived `receipt.corpus` without reconstructing or
editing it. After writing the receipt:

```bash
stinger benchmark sign-corpus-construction-receipt \
  /new/path/corpus-construction-receipt.json \
  --private-key /access-controlled/path/corpus-construction-key

stinger benchmark verify-corpus-construction-receipt \
  /new/path/corpus-construction-receipt.json \
  --signature /new/path/corpus-construction-receipt.json.sig \
  --allowed-signers /separately-supplied/path/corpus_construction_allowed_signers \
  --signer-identity corpus-construction@example.org
```

The receipt embeds the fully derived corpus record and exact construction inventories while
rejecting private paths, canary values, symlinks, aliasing, missing evidence, and
post-verification mutation.

## Artifact-derived pilot evidence

Run the anonymous non-saturation pilot against the exact promoted, constructed corpus
before freezing it. Supply one aligned alias/public-bundle/escrow-bundle/protocol-trust
tuple per anonymous configuration; repeat those five options together. Scenario inclusion,
repetition count, alias rules, and the variation threshold come from the closed policy in
the signed benchmark protocol; the builder accepts no caller-authored selection file.

```bash
stinger benchmark build-pilot-evidence \
  --corpus-record /new/path/unfrozen-sealed-corpus-record.json \
  --candidate-receipt /new/public/path/candidate-validation-receipt.json \
  --configuration-alias anonymous-0000000000000001 \
  --public-bundle /verified/path/pilot-public-bundle-1 \
  --escrow-bundle /access-controlled/path/pilot-escrow-bundle-1 \
  --protocol-allowed-signers /separately-supplied/path/protocol_allowed_signers \
  --protocol-signer-identity stinger-release@example.org \
  --forbidden-source /access-controlled/path/promoted-corpus-package/corpus \
  --marker-file /access-controlled/path/canary-value \
  --marker-file /access-controlled/path/dummy-secret-value \
  --output /new/path/pilot-evidence-statement.json

stinger benchmark sign-pilot-evidence \
  /new/path/pilot-evidence-statement.json \
  --private-key /access-controlled/path/pilot-evidence-key
```

The pilot statement is path-free, binds the candidate receipt and exact promoted corpus,
and is signed under `stinger-benchmark-pilot-evidence`. Its signer identity, verified key,
and trust policy must differ from Chris's final release authorization.

## Corpus freeze

After signed promotion, artifact-derived construction, and signed pilot evidence exist,
derive and sign the exact freeze statement from the complete unfrozen
`SealedCorpusRecord`:

```bash
stinger benchmark build-corpus-freeze-statement \
  --corpus-record /access-controlled/path/sealed-corpus-record.json \
  --protocol benchmark/protocol.yaml \
  --candidate-receipt /new/public/path/candidate-validation-receipt.json \
  --candidate-receipt-signature /new/public/path/candidate-validation-receipt.json.sig \
  --candidate-receipt-allowed-signers \
    /separately-supplied/path/candidate_allowed_signers \
  --candidate-receipt-signer-identity candidate-validation@example.org \
  --candidate-promotion-statement \
    /new/access-controlled/path/promoted-corpus-package/candidate-promotion-statement.json \
  --candidate-promotion-signature \
    /new/access-controlled/path/promoted-corpus-package/candidate-promotion-statement.json.sig \
  --candidate-promotion-allowed-signers \
    /separately-supplied/path/candidate_promotion_allowed_signers \
  --candidate-promotion-signer-identity candidate-promotion@example.org \
  --signer-identity corpus-freeze@example.org \
  --output /new/path/corpus-freeze-statement.json

stinger benchmark sign-corpus-freeze \
  /new/path/corpus-freeze-statement.json \
  --private-key /access-controlled/path/corpus-freeze-key

stinger benchmark build-corpus-freeze-record \
  --statement /new/path/corpus-freeze-statement.json \
  --signature /new/path/corpus-freeze-statement.json.sig \
  --allowed-signers /separately-supplied/path/corpus_freeze_allowed_signers \
  --signer-identity corpus-freeze@example.org \
  --output /new/path/corpus-freeze-record.json
```

The first builder reruns the machine corpus-construction gate and binds the protocol and
rubric versions, sealed corpus hash and inventory, candidate receipt, signed promotion,
custody inventory, cooperative access-log root, canary receipt, and aggregate family/size
counts. The signed record belongs in `SealedCorpusRecord.freeze`; `release-check`
separately verifies the exact statement, detached signature, signer identity, and supplied
trust policy. A presence-only hash or hand-entered favorable Boolean is not a freeze.

## Release and reproduction roles

Protocol signing freezes the rules; it does not authorize publication. After every machine
gate and evidence field is final, Chris signs the exact release submission:

The command template in this section is the final step. Construct the public/escrow,
machine, baseline, conformance, release-evidence, and reproduction artifacts in the later
sections before using it.

```bash
stinger benchmark sign-release /access-controlled/path/release-submission.yaml \
  --private-key /access-controlled/path/release-key
```

The cross-machine execution role separately signs:

1. the exact reproduced `report.json` bytes under
   `stinger-benchmark-reproduced-report`; and
2. the artifact-derived reproduction statement under
   `stinger-benchmark-reproduction`.

The final release gate receives twelve all-or-nothing groups. In the command below, repeat
the four `--conformance-*` options once per submitted conformance environment and the four
`--baseline-verification-*` options once per baseline configuration:

```bash
stinger benchmark release-check /access-controlled/path/release-submission.yaml \
  --protocol benchmark/protocol.yaml \
  --protocol-signature benchmark/protocol.yaml.sig \
  --protocol-allowed-signers /separately-supplied/path/protocol_allowed_signers \
  --protocol-signer-identity stinger-release@example.org \
  --candidate-receipt /public/path/candidate-validation-receipt.json \
  --candidate-receipt-signature /public/path/candidate-validation-receipt.json.sig \
  --candidate-receipt-allowed-signers \
    /separately-supplied/path/candidate_allowed_signers \
  --candidate-receipt-signer-identity candidate-validation@example.org \
  --candidate-promotion-statement \
    /access-controlled/path/candidate-promotion-statement.json \
  --candidate-promotion-signature \
    /access-controlled/path/candidate-promotion-statement.json.sig \
  --candidate-promotion-allowed-signers \
    /separately-supplied/path/candidate_promotion_allowed_signers \
  --candidate-promotion-signer-identity candidate-promotion@example.org \
  --corpus-construction-receipt \
    /access-controlled/path/corpus-construction-receipt.json \
  --corpus-construction-signature \
    /access-controlled/path/corpus-construction-receipt.json.sig \
  --corpus-construction-allowed-signers \
    /separately-supplied/path/corpus_construction_allowed_signers \
  --corpus-construction-signer-identity corpus-construction@example.org \
  --corpus-freeze-statement /access-controlled/path/corpus-freeze-statement.json \
  --corpus-freeze-signature /access-controlled/path/corpus-freeze-statement.json.sig \
  --corpus-freeze-allowed-signers \
    /separately-supplied/path/corpus_freeze_allowed_signers \
  --corpus-freeze-signer-identity corpus-freeze@example.org \
  --pilot-evidence-statement /access-controlled/path/pilot-evidence-statement.json \
  --pilot-evidence-signature /access-controlled/path/pilot-evidence-statement.json.sig \
  --pilot-evidence-allowed-signers \
    /separately-supplied/path/pilot_evidence_allowed_signers \
  --pilot-evidence-signer-identity pilot-evidence@example.org \
  --conformance-statement /public/path/conformance-statement-1.json \
  --conformance-signature /public/path/conformance-statement-1.json.sig \
  --conformance-allowed-signers \
    /separately-supplied/path/conformance_1_allowed_signers \
  --conformance-signer-identity conformance-1@example.org \
  --baseline-verification-statement /public/path/baseline-verification-1.json \
  --baseline-verification-signature /public/path/baseline-verification-1.json.sig \
  --baseline-verification-allowed-signers \
    /separately-supplied/path/baseline_verification_allowed_signers \
  --baseline-verification-signer-identity baseline-verification@example.org \
  --release-evidence-statement /public/path/release-evidence-statement.json \
  --release-evidence-signature /public/path/release-evidence-statement.json.sig \
  --release-evidence-allowed-signers \
    /separately-supplied/path/release_evidence_allowed_signers \
  --release-evidence-signer-identity release-evidence@example.org \
  --signature /access-controlled/path/release-submission.yaml.sig \
  --allowed-signers /separately-supplied/path/release_allowed_signers \
  --signer-identity stinger-release@example.org \
  --reproduction-statement /cross-machine/path/reproduction-statement.json \
  --reproduction-signature /cross-machine/path/reproduction-statement.json.sig \
  --verifier-allowed-signers /separately-supplied/path/reproduction_allowed_signers \
  --verifier-identity cross-machine-role@example.org \
  --public-reproduction-verification-statement \
    /public/path/public-reproduction-verification.json \
  --public-reproduction-verification-signature \
    /public/path/public-reproduction-verification.json.sig
```

The twelve groups are: protocol; candidate receipt; candidate promotion; corpus
construction receipt; corpus freeze; pilot evidence; repeatable conformance; repeatable
baseline verification; release evidence; final release; reproduction statement; and public
reproduction-verification handoff. The command may be run without one or more complete groups to
inspect blocking issue codes, but it cannot become `machine_reproduced` until every group
is supplied and mutually bound.

The release and reproduction roles must use different signer identities, verified signing
keys, policies, and namespaces. This proves cryptographic role separation. It does not
prove that two organizations or two people participated.

The pilot-evidence and release-evidence roles must also differ from the final release role.
The conformance authorizations must satisfy the protocol's distinct signing-key and
trust-policy counts. Baseline verification requires one exact signed statement for every
submitted baseline; a record inside the signed submission is not sufficient by itself.

Chris's release signature authorizes publication after all machine gates pass. It is not a
scenario review, transcript review, outcome label, score, or substitute for missing
evidence.

## Public bundle

`bundle-public` accepts protocol/config/report artifacts plus an explicit allowlist of
publishable logs. It requires:

- the detached protocol signature and signer policy;
- at least one active sealed source for exact-file comparison; and
- marker files containing every active canary and dummy-secret value.

Marker values are read from files so they do not appear in process arguments. The command
rejects exact sealed files, bounded raw chunks and token n-grams copied from sealed
material, canary/secret substrings, private or escrow absolute paths, sensitive path roles,
private-key material, symlinks, extra files, and any hash/size/mode mismatch. The bounded
chunk and n-gram comparison catches straightforward prompt/reference near-copies without
treating short common language as sealed evidence. Verification reruns the same leakage
policy and protocol trust checks.

Run `stinger benchmark bundle-public --help` and
`stinger benchmark verify-public --help` for the complete interfaces.

## Escrow bundle

`bundle-escrow` copies the full sealed corpus and rerunnable evidence, verifies its exact
inventory, and embeds a conspicuous warning. It is **not encrypted**. Create it only in an
access-controlled destination and transfer it only through a channel authorized for active
benchmark material.

For current benchmark evidence, escrow verification also reconstructs every
classification from the exact sealed scenario, transcript, retained final worktree, and
closed-schema command observations in `classification.replay.json`. It replays the
configured transcript parser and reruns the held-out completion check and suite in the
pinned network-disabled verification image. The replay record contains no outcome,
detector verdict, goal/claim decision, refusal decision, or run error; those fields must be
derived again and match `report.json`. Historical development packages remain readable,
but they cannot satisfy this benchmark escrow contract.

Run `stinger benchmark bundle-escrow --help` and
`stinger benchmark verify-escrow --help` for the complete interfaces.

The accepted baseline record binds exact public and escrow `bundle.manifest.json` bytes.
A successful bundle check is necessary but does not replace machine construction, QA,
blind solves, conformance, cross-machine reproduction, or final signed release
authorization.

## Machine environment and workflow attestation

Create the privacy-preserving identity on the host that performed the workflow, then bind
that host identity to the exact workflow input, output receipt, and clean Stinger commit:

```bash
stinger benchmark create-machine-environment-identity \
  --output /machine/path/machine-identity.json

stinger benchmark build-machine-workflow-attestation \
  --machine-identity /machine/path/machine-identity.json \
  --workflow-input /machine/path/workflow-input.json \
  --workflow-receipt /machine/path/workflow-receipt.json \
  --repository /clean/path/stinger \
  --expected-stinger-commit FULL_GIT_COMMIT \
  --signer-identity machine-workflow@example.org \
  --output /machine/path/machine-workflow-attestation.json

stinger benchmark sign-machine-workflow-attestation \
  /machine/path/machine-workflow-attestation.json \
  --private-key /machine/path/machine-workflow-key

stinger benchmark verify-machine-workflow-attestation \
  --machine-identity /machine/path/machine-identity.json \
  --workflow-input /machine/path/workflow-input.json \
  --workflow-receipt /machine/path/workflow-receipt.json \
  --attestation /machine/path/machine-workflow-attestation.json \
  --signature /machine/path/machine-workflow-attestation.json.sig \
  --allowed-signers /separately-supplied/path/machine_workflow_allowed_signers \
  --signer-identity machine-workflow@example.org \
  --expected-stinger-commit FULL_GIT_COMMIT
```

The baseline, conformance, and reproduction builders define the exact workflow input and
receipt that must be used for their role. Do not substitute an arbitrary “machine identity”
file. The host-derived commitment is not TPM, physical-hardware, cloud-provider,
organizational-independence, or anti-cloning proof.

## Artifact-derived baseline records

Accepted baseline records are constructed by the verifier-side builder, never by
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
  --allowed-signers /separately-supplied/path/protocol_allowed_signers \
  --signer-identity stinger-release@example.org \
  --machine-identity /machine/path/machine-identity.json \
  --machine-attestation /machine/path/machine-workflow-attestation.json \
  --machine-attestation-signature /machine/path/machine-workflow-attestation.json.sig \
  --machine-attestation-allowed-signers \
    /separately-supplied/path/machine_workflow_allowed_signers \
  --machine-attestation-signer-identity machine-workflow@example.org \
  --output /new/path/baseline-record.json

stinger benchmark build-baseline-verification \
  --configuration-id pinned-configuration-id \
  --baseline-record /new/path/baseline-record.json \
  --corpus-record /access-controlled/path/sealed-corpus-record.json \
  --public-bundle /verified/path/public-bundle \
  --escrow-bundle /access-controlled/path/escrow-bundle \
  --forbidden-source /access-controlled/path/active-sealed-corpus \
  --marker-file /access-controlled/path/canary-value \
  --marker-file /access-controlled/path/dummy-secret-value \
  --protocol-allowed-signers /separately-supplied/path/protocol_allowed_signers \
  --protocol-signer-identity stinger-release@example.org \
  --machine-identity /machine/path/machine-identity.json \
  --machine-attestation /machine/path/machine-workflow-attestation.json \
  --machine-attestation-signature /machine/path/machine-workflow-attestation.json.sig \
  --machine-attestation-allowed-signers \
    /separately-supplied/path/machine_workflow_allowed_signers \
  --machine-attestation-signer-identity machine-workflow@example.org \
  --statement-signer-identity baseline-verification@example.org \
  --output /new/path/baseline-verification-statement.json

stinger benchmark sign-baseline-verification \
  /new/path/baseline-verification-statement.json \
  --private-key /access-controlled/path/baseline-verification-key
```

The command:

- re-verifies both bundles under the supplied leakage and protocol-trust policies;
- snapshots and cross-binds exact manifest, report, configuration, signature, and trust
  bytes;
- re-scores the report and verifies uncertainty, publication pins, Docker containment,
  observed runtime provenance, and deterministic blocked order;
- rejects every baseline containing an `ERROR` result; and
- runs the same per-configuration evaluator used by the final release gate.

There is no error-disposition input. `report_sha256` is the canonical typed-report hash.
Bundle hashes cover the exact verified `bundle.manifest.json` bytes, not an internal
inventory field. The builder writes canonical JSON atomically to a new path and never
prints or copies escrow contents.

Run this record/rebuild/sign sequence for every baseline configuration. The final
`release-check` receives the aligned statement, signature, separately supplied trust
policy, and expected signer identity for each one.

The machine input is a canonical host-derived environment identity plus a signed workflow
attestation over the exact resolved configuration, report, and clean commit. The raw
operating-system identifier is never emitted. Its application-scoped commitment detects
reuse or disagreement, but it is not TPM, physical-hardware, cloud-provider,
organizational-independence, or anti-cloning proof. Likewise, `contained` means the
verified configuration required Docker and stored runtime provenance matched pinned images
and invocation; it is not independent per-process hardware telemetry.

The public `release-check` does not receive the active corpus, escrow, markers, or leakage
policy. It consumes the record inside the signed submission plus the separately authorized
baseline-verification statement.

Provider diversity is credited only when the pinned metadata and observed local command use
the canonical adapter mapping (`codex`/OpenAI, `claude-code`/Anthropic, or provider-prefixed
`aider`). `shell` and `recorded` runs do not count. These checks prevent relabeling a local
CLI invocation, but they are not provider-signed remote account, endpoint, service, or
served-model attestations.

Benchmark execution automatically creates a deterministic run plan, a fresh evidence-only
pre-invocation challenge for every scenario/repetition, a post-classification
`invocation.receipt.json`, and a run-level invocation aggregate. These artifacts bind every
planned row to its transcript, replay record, diffs, final worktree state, and result.
Escrow verification requires complete coverage and rejects duplicate invocation IDs,
challenge commitments, execution-evidence commitments, and supported provider response IDs.
The random challenge is never placed in the prompt and never affects scoring.

Every brokered invocation also creates `credential-isolation.receipt.json`. It is bound to
the same invocation ID and runtime-provenance hash and records only non-secret commitments:
the signed policy; exact loaded broker configuration, source, immutable image, effective
allowed destination, startup-resolved provider IPv4 inventory, and minimal agent projection;
Docker runtime; raw/hex/Base64/URL-safe-Base64/percent scan of
the final argv, workdir, image metadata, and exported final rootfs; signed prohibited-path and
empty-config-home checks; agent/broker/two-network, command, environment, mount, and attachment
inventories; isolated gateway, IPv6, DNS, disabled-healthcheck, deadline, and concurrency
state; broker audit/counts; direct internal/outbound network ID/name hashes; and a distinct
verified-cleanup field for each network. `invocation.receipt.json` binds its exact file hash, and the run
aggregate binds the complete ordered set. Missing, extra, duplicated, noncanonical, drifted,
rejected-request, encoded-credential, bypass, arbitrary-egress, or cleanup-failure evidence
is fatal. The receipt does not turn the still-unapproved agent image into a supply-chain
claim.

Codex and Claude Code transcripts must each contain one unique structured provider session
identifier. Aider exposes no equivalent canonical provider-side identifier, so a valid
Aider receipt proves distinct signed runner challenges, not distinct provider-attested
remote calls. The run-level aggregate is the non-circular inner receipt. Once the public
and escrow bundles exist, a separately signed machine-workflow input binds the aggregate
hash and both exact `bundle.manifest.json` hashes; replacing either the aggregate or a
bundle therefore invalidates the external authorization.

## Machine conformance records

Protocol 2 requires at least three `ConformanceEnvironmentRecord` entries with distinct
environment IDs and fingerprints spanning at least two platform/architecture pairs. Each
record binds:

- platform, architecture, and Python version;
- exact clean Stinger commit;
- benchmark protocol version, rubric version, and active corpus hash;
- environment fingerprint;
- workflow input and workflow receipt hashes; and
- receipt signature hash, signer identity, and supplied `allowed_signers` policy hash.

For each clean environment:

```bash
stinger benchmark run-conformance-workflow \
  --repository /clean/path/stinger \
  --toolchain-python /external/toolchain/bin/python \
  --expected-stinger-commit FULL_GIT_COMMIT \
  --corpus-hash ACTIVE_SEALED_CORPUS_SHA256 \
  --output-package /machine/private/conformance-workflow

stinger benchmark build-conformance-statement \
  --environment-id clean-environment-1 \
  --corpus-hash ACTIVE_SEALED_CORPUS_SHA256 \
  --workflow-input \
    /machine/private/conformance-workflow/conformance-workflow-input.json \
  --workflow-output-inventory \
    /machine/private/conformance-workflow/conformance-workflow-receipt.json \
  --workflow-output \
    /machine/private/conformance-workflow/conformance-workflow-output.bin \
  --machine-identity /machine/path/machine-identity.json \
  --machine-attestation /machine/path/machine-workflow-attestation.json \
  --machine-attestation-signature /machine/path/machine-workflow-attestation.json.sig \
  --machine-attestation-allowed-signers \
    /separately-supplied/path/machine_workflow_allowed_signers \
  --repository /clean/path/stinger \
  --signer-identity conformance-1@example.org \
  --output /new/path/conformance-statement-1.json

stinger benchmark sign-conformance \
  /new/path/conformance-statement-1.json \
  --private-key /machine/path/conformance-key-1

stinger benchmark build-conformance-record \
  --statement /new/path/conformance-statement-1.json \
  --signature /new/path/conformance-statement-1.json.sig \
  --allowed-signers /separately-supplied/path/conformance_1_allowed_signers \
  --signer-identity conformance-1@example.org \
  --output /new/path/conformance-record-1.json
```

The run command snapshots the clean tracked source tree, invokes the fixed
`bash scripts/check.sh` workflow with the explicitly supplied Python toolchain, and writes
exactly the canonical input, typed receipt, and raw output shown above. The receipt binds
the observed executable and installed-distribution inventory before and after the run.
This is a strong local execution receipt, not a hermetic or remotely attested toolchain:
the external Python installation remains part of the stated machine environment.

All environments must bind the same workflow input and the one baseline commit. Environment
IDs, environment fingerprints, workflow receipts, and receipt signatures must meet the
gate's distinct-count requirements. Their conformance authorizations must also use the
required number of distinct verified signing keys and trust policies. `release-check`
therefore receives each signed statement and its separately supplied trust policy in
addition to the typed records inside the release submission.

The conformance workflow uses the public development suite. It tests installation and
operation across clean environments; it does not inspect or disclose the active sealed
corpus.

## Artifact-derived release evidence

Release evidence is deliberately two-stage so the evidence record can be inserted into the
final submission before that exact submission is hashed and signed. Stage 1 runs the master
gate exactly once, preserves its exact merged output in a private preparation package, and
writes the public record:

First generate the four closed artifacts from a typed draft submission. The draft may still
contain an empty `release_evidence` record because the builder deliberately ignores that
future circular field:

```bash
stinger benchmark build-release-artifacts \
  --submission /access-controlled/path/draft-release-submission.yaml \
  --conflicts-declaration no-known-material-conflicts \
  --output /new/access-controlled/path/release-artifacts
```

If material relationships exist, use
`--conflicts-declaration material-conflicts-disclosed` and repeat
`--conflict CATEGORY ENTITY DESCRIPTION` for every relationship. This is a signed
attestation: Stinger verifies complete configuration/provider scope, canonical structure,
and exact bytes, but does not claim it can discover an omitted real-world relationship.

The generated `technical-report.json` is the gate artifact. It is a deterministic seven-part
evidence index derived from the typed submission and contains no caller-authored narrative.
`protocol-freeze.json`, `correction-policy.json`, and `conflicts-disclosure.json` are also
closed canonical schemas. Arbitrary Markdown, plaintext, unknown fields, omitted correction
actions, or mismatched freeze/configuration/provider scope fail closed.

```bash
stinger benchmark build-release-evidence-record \
  --repository /clean/path/stinger \
  --toolchain-python /external/toolchain/bin/python \
  --expected-stinger-commit FULL_GIT_COMMIT \
  --corpus-version 1.0.0 \
  --corpus-hash ACTIVE_SEALED_CORPUS_SHA256 \
  --protocol-freeze-receipt /new/access-controlled/path/release-artifacts/protocol-freeze.json \
  --technical-report /new/access-controlled/path/release-artifacts/technical-report.json \
  --correction-policy /new/access-controlled/path/release-artifacts/correction-policy.json \
  --conflicts-disclosure /new/access-controlled/path/release-artifacts/conflicts-disclosure.json \
  --non-comparative-release \
  --preparation-package /access-controlled/path/release-evidence-preparation \
  --output /new/path/release-evidence-record.json
```

Comparative release evidence is deliberately on HOLD. `--comparative-release` and any
`--vendor-rerun-receipt` fail until a dedicated externally signed vendor-opportunity schema
and trust path exist. Insert the resulting non-comparative record into the release submission
and finalize every other submission field. Stage 2 reloads and
re-verifies the same clean commit, exact artifacts, canonical private receipt, and preserved
gate-output bytes; it does **not** execute `check.sh` again:

```bash
stinger benchmark build-release-evidence-statement \
  --submission /access-controlled/path/release-submission.yaml \
  --signer-identity release-evidence@example.org \
  --repository /clean/path/stinger \
  --expected-stinger-commit FULL_GIT_COMMIT \
  --corpus-version 1.0.0 \
  --corpus-hash ACTIVE_SEALED_CORPUS_SHA256 \
  --protocol-freeze-receipt /new/access-controlled/path/release-artifacts/protocol-freeze.json \
  --technical-report /new/access-controlled/path/release-artifacts/technical-report.json \
  --correction-policy /new/access-controlled/path/release-artifacts/correction-policy.json \
  --conflicts-disclosure /new/access-controlled/path/release-artifacts/conflicts-disclosure.json \
  --non-comparative-release \
  --preparation-package /access-controlled/path/release-evidence-preparation \
  --output /new/path/release-evidence-statement.json

stinger benchmark sign-release-evidence \
  /new/path/release-evidence-statement.json \
  --private-key /access-controlled/path/release-evidence-key
```

The signed release-evidence statement embeds the parsed typed manifest. `release-check`
reparses the exact signed statement bytes, re-derives every artifact from the final
submission, and requires their canonical artifact hashes to equal the submission record.
Directly signing a hand-authored favorable hash record does not bypass this check.

The preparation directory is private and create-only. It contains exactly
`preparation-receipt.json`, `master-gate-receipt.json`, and the original
`master-gate-output.bin`. The typed master-gate receipt binds the clean tracked-source
snapshot, fixed command, explicit external Python executable, executable hashes, installed
distribution inventory, and exact output bytes. Missing, extra, symlinked, mutated,
partial, or substituted contents fail closed.

This is strong local signed-toolchain evidence, not a hermetic build, remote service
attestation, or independently trusted CI result. The supplied Python installation is an
explicit part of the claim boundary. The statement uses
`stinger-benchmark-release-evidence`; its signer identity, verified key, and trust policy
must differ from Chris's final release authorization.

## Artifact-derived cross-machine reproduction

First sign the exact reproduced report:

```bash
stinger benchmark sign-reproduced-report /cross-machine/path/report.json \
  --private-key /cross-machine/path/reproduction-key
```

Then produce the automatic comparison ledger:

```bash
stinger benchmark reproduction-diff \
  /cross-machine/path/target-report.json \
  /cross-machine/path/reproduced-report.json \
  --output /cross-machine/private/reproduction-diff.json
```

The two reports must have identical scenario/family sets, repetition indices, sealed
split, scenario versions, clusters, protocol, corpus, configuration, and agent
fingerprints. A structural difference fails immediately. Modal outcomes must also match
exactly.

Only these classification-relevant fields may produce per-run discrepancies:

- `outcome`
- `detector_results`
- `goal_met`
- `agent_claimed_done`
- `run_error`

Timestamps, durations, and transcript/diff path strings are run-specific noise; their
underlying evidence remains bound by bundle inventories. Each permitted discrepancy gets
a deterministic ID and the fixed classification
`expected_agent_variance_modal_stable`. The ledger is not a review template: it has no
editable resolution, resolved Boolean, free text, waiver, or override.

`stinger benchmark build-reproduction-statement --help` lists the complete private
workflow. It requires the accepted target record, both target bundle paths, both separately
constructed reproduced bundle paths, active leakage policy, protocol trust, distinct
host-derived machine identities with their signed workflow-attestation chains, and the
reproduced-report signature/trust chain.

The builder:

- re-verifies both public/escrow pairs;
- reconstructs the supplied target baseline and requires exact equality;
- derives a publication-eligible reproduced-side record;
- verifies the exact reproduced-report signature;
- recomputes a reproduced-minus-target paired comparison at 10,000 draws, seed 0, and 95%
  confidence;
- verifies the automatic discrepancy ledger and exact modal-outcome equality; and
- rejects aliased inputs, copied target evidence, private-path disclosure, active markers,
  and output paths inside any input tree.

It atomically creates a new directory containing:

- `comparison.manifest.json`
- `discrepancy-ledger.json`
- `reproduction-statement.json`

Every report, signature, bundle-manifest, machine, comparison, modal-outcome, and ledger
hash is derived from verified exact bytes or a canonical typed value. No unaffiliated
attestation or manual reconciliation file is accepted.

After the statement is signed under the reproduction namespace, derive the public record:

```bash
stinger benchmark sign-reproduction \
  /cross-machine/private/output/reproduction-statement.json \
  --private-key /cross-machine/path/reproduction-key

stinger benchmark build-reproduction-record \
  --statement /cross-machine/private/output/reproduction-statement.json \
  --signature /cross-machine/private/output/reproduction-statement.json.sig \
  --allowed-signers /separately-supplied/path/reproduction_allowed_signers \
  --signer-identity cross-machine-role@example.org \
  --output /new/path/cross-machine-reproduction-record.json
```

Before `release-check`, run the separate full public verification step. This is the only
stage below that receives the active leakage comparison material:

```bash
stinger benchmark verify-public-reproduction \
  --reproduction-statement \
    /cross-machine/private/output/reproduction-statement.json \
  --reproduction-signature \
    /cross-machine/private/output/reproduction-statement.json.sig \
  --verifier-allowed-signers \
    /separately-supplied/path/reproduction_allowed_signers \
  --verifier-identity cross-machine-role@example.org \
  --target-baseline-record /verified/path/target-baseline-record.json \
  --target-public-bundle /verified/path/target-public-bundle \
  --reproduced-public-bundle /cross-machine/path/public-bundle \
  --forbidden-source /access-controlled/path/active-sealed-corpus \
  --marker-file /access-controlled/path/active-canaries.txt \
  --protocol-allowed-signers \
    /separately-supplied/path/protocol_allowed_signers \
  --protocol-signer-identity protocol-authority@example.org \
  --reproduced-report-signature /cross-machine/path/report.json.sig \
  --comparison-manifest \
    /cross-machine/private/output/comparison.manifest.json \
  --discrepancy-ledger \
    /cross-machine/private/output/discrepancy-ledger.json \
  --output /new/public/path/public-reproduction-verification.json

stinger benchmark sign-public-reproduction-verification \
  /new/public/path/public-reproduction-verification.json \
  --private-key /cross-machine/path/reproduction-key
```

The verifier derives the target and reproduced report bytes only from those independently
verified public bundles. A standalone report path cannot substitute for either bundle.

The verifier emits no caller-entered favorable Boolean. Its closed statement derives the
authorized reproduction hash; target baseline, report, and public-manifest hashes;
reproduced full public inventory, leakage-policy, report, protocol-signature, and trust
hashes; report-signature trust; comparison and discrepancy hashes; and evaluator
identity/key/trust. The dedicated signature namespace prevents substituting the original
reproduction or report signature.

`release-check` then receives the signed reproduction statement and the signed non-secret
verification statement. It verifies those exact bytes against the separately supplied
evaluator trust policy and cross-binds them to the submission. It never opens a bundle,
report, escrow tree, sealed corpus, marker file, or leakage policy.
