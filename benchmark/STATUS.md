# Stinger Benchmark v1 status

Overall status: **benchmark candidate — HOLD on benchmark or vendor-comparison claims**

This table records evidence, not intention. `met` requires a committed or mechanically
verifiable artifact. A count of candidate directories is not a benchmark release.

| Gate | Required | Current evidence | State |
|---|---:|---|---|
| Public development corpus | 30, six per family | `scenarios/` validates 30/30 in CI | met |
| Current-corpus live evidence | Contained, all five families, five repetitions, fully pinned | Historical T/S/C locks differ, G alone matches, and no X run exists | not met |
| Private candidate construction | 120, 24 per family, balanced sizes, four variants each | An older internal checkpoint asserts 120 candidates, 8/8/8 sizes per family, 480/480 variant checks, and 120/120 contained validity checks; no current signed Protocol 2 construction receipt accepts those assertions | internal checkpoint only; Protocol 2 acceptance not met |
| Candidate validation receipt | Exact non-secret receipt derived from a safe snapshot | Existing authoring records are heterogeneous and bind an older commit; no accepted Protocol 2 receipt exists | not met |
| Sealed scored corpus | 120, 24 per family | Candidate is not Protocol 2 accepted, piloted, frozen, or sealed | not met |
| Candidate custody | Inventory, canaries, access-log root, freeze receipt | Owner-only external storage and 120 canaries verify; current cooperative hash chain is bypassable and is not a release-grade access log | partial; release gate not met |
| Machine scenario review | Two bound reviews across two providers per scored scenario | Frozen veto contract exists; no accepted 120-scenario review matrix exists | mechanism met; evidence not met |
| Resolution variants | Two honest and two cheat variants per scenario, each artifact-bound | Candidate authoring checks exist; Protocol 2 artifact receipts are not yet accepted | partial; release gate not met |
| Agent QA | Five attempts per scenario across two configurations and two providers | No accepted scored-corpus QA matrix exists | not met |
| Blind agent solves | Six deterministic scenarios per family, two reference-isolated solvers across two providers/configurations | No accepted solve records exist | not met |
| Verification-image supply chain | Signed exact Dockerfile/hashed-lock inventory plus ordered OCI manifest/config identities keyed by target platform, enforced before verifier execution | Protocol 2 policy names both Docker-store identity representations from byte-identical clean exports for linux/amd64 and linux/arm64; claim remains bounded to Docker daemon/admin observations | mechanism met |
| Agent-image supply chain | Signed exact source/attestation policy for every networked agent image that executes sealed prompts | Agent image IDs are recorded, but no signed source or attestation allowlist approves their executable bytes | **HOLD; not implemented** |
| Credential isolation for sealed execution | Raw provider credentials remain outside the agent container; provider-allowlisted egress broker and exact projection/config receipt are mechanically bound | Current agent containers receive raw Codex/Claude credentials and ordinary `credential_mount` directories are not content-bound | **HOLD; not implemented** |
| Exact-snapshot anonymous pilot | Promote the complete candidate snapshot without content changes, require at least 20% outcome variation, then freeze that same set | No accepted artifact-derived pilot record exists | not met |
| Fully pinned baseline configs | Six across three providers | Existing evidence does not meet benchmark pins | not met |
| Contained five-family baselines | Five repetitions per configuration | No complete sealed baseline exists | not met |
| Statistical publication mechanism | Clustered/paired intervals, nested repetitions, tamper check | Implemented and tested; no eligible sealed baseline exists | mechanism met; evidence not met |
| Deterministic blocked ordering | Fixed-seed family blocks, rechecked from results | Implemented and tested; no eligible sealed baseline exists | mechanism met; evidence not met |
| Public/escrow evidence mechanism | Signed protocol, leakage-checked public bundle, full escrow | Implemented and tested, including sealed-artifact CI refusal; no release bundle exists | mechanism met; evidence not met |
| Clean conformance environments | Three fingerprints across two platform/architecture pairs | None accepted | not met |
| Cross-machine reproduction | One complete baseline, exact modal agreement, signed artifact binding | Builder/gate implementation is under Protocol 2 review; no real reproduction exists | evidence not met |
| Signed frozen protocol | Trusted detached signature over exact Protocol 2 bytes | Signing mechanism exists; no accepted Protocol 2 signature is claimed | not met |
| Technical report and disclosures | Deterministic report index, fixed correction policy, scoped conflicts declaration, typed freeze binding, signed exact record | Closed builders/gate are implemented; no real release-artifact package or signed release statement exists | mechanism met; evidence not met |
| Master release gate | Corpus, matrix, conformance, reproduction, and signed operator authorization | `candidate-submission.yaml` fails closed with stable issue codes | release not met |
| Operator release authorization | Chris signs the exact completed submission after all machine gates | Not requested because prior gates are open | not met |

The existing live packages remain valuable instrument checks, but they are partial,
pre-benchmark evidence and are not promoted by this document. No human scenario review,
manual transcript review, beta-operator record, editable error disposition, or free-text
reproduction reconciliation is a Protocol 2 release gate.

No live sealed review, QA, blind solve, pilot, baseline, or reproduction is authorized with
the current credential or agent-image paths. The signed verification-image policy approves
only the network-disabled verifier; it says nothing about the networked agent container. A
read-only mount and post-run secret scan do not isolate a
credential from an untrusted, networked agent process. The ordinary run path also records
only that a credential directory was mounted; it does not bind every copied file, so hidden
CLI configuration or session state could change a run without changing its published
identity. The HOLD remains until an external, provider-allowlisted credential-injecting
broker (or equivalent design that keeps raw credentials outside the agent container) and an
exact minimal projection/config receipt are implemented, tested, and bound into evidence.

Run `stinger benchmark release-check benchmark/candidate-submission.yaml` for the
machine-readable current blocker list. A non-zero exit is the expected truthful result.
