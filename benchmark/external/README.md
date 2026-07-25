# Machine conformance and cross-machine workflow

Protocol 2 uses artifact-bound environment evidence instead of beta-operator reports.

The public development/conformance workflow must complete in at least three clean,
fingerprint-distinct environments spanning at least two platform/architecture pairs. Each
`ConformanceEnvironmentRecord` binds its environment ID, platform, architecture, Python
version, exact Stinger commit, benchmark protocol version, rubric version, active corpus
hash, environment fingerprint, workflow input and receipt hashes, receipt signature hash,
signer identity, and supplied trust-policy hash. All records must bind the same workflow
input and the one baseline commit; the required environment, receipt, and signature
distinctness and platform diversity fail closed.

The record is an artifact binding, not an assertion that merely naming a signer proves
execution. The workflow that creates it must preserve the separately supplied trust
evidence whose exact hashes the record carries.

After protocol and corpus freeze, one complete five-family sealed baseline is reproduced
under the same protocol, corpus, configuration, and agent fingerprints with separately
constructed public/escrow bundles, a distinct host-derived environment commitment, and
separately signed workflow evidence.

The artifact-derived builder verifies both target and reproduced bundle pairs, target
baseline equality, report signatures, structural identity, modal outcomes, deterministic
ordering, statistics, containment, pins, and leakage policy. It emits an automatic
classification-only discrepancy ledger. Structural or modal mismatch is fatal; a
per-repetition difference may carry only
`expected_agent_variance_modal_stable`. There is no free-text resolution or override.

The cross-machine role signs the exact reproduced report and then the derived reproduction
statement under separate namespaces. `release-check` receives the signed statement and
separately supplied trust policy; it does not receive the active corpus or escrow.

These controls establish machine evidence and cryptographic role separation. The
host-derived commitments detect environment reuse or disagreement, but do not prove TPM
or physical hardware identity, cloud-provider origin, organizational affiliation,
operator independence, or resistance to cloning. Chris's separate final release signature
remains required after all machine gates pass; it authorizes publication and is not a run
review.
