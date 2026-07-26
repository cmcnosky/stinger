# Stinger Benchmark v1 status

Overall status: **benchmark candidate — HOLD on benchmark or vendor-comparison claims**

This table records evidence, not intention. `met` requires a committed or mechanically
verifiable artifact. A count of candidate directories is not a benchmark release.

| Gate | Required | Current evidence | State |
|---|---:|---|---|
| Public development corpus | 30, six per family | `scenarios/` validates 30/30 in CI | met |
| Current-corpus live evidence | Contained, all five families, five repetitions, fully pinned | Historical T/S/C locks differ, G alone matches, and no X run exists | not met |
| Private candidate construction | 120, 24 per family, balanced sizes, four variants each | The signed candidate receipt proves the 120-candidate aggregate shape and 120/120 contained validity; older authoring records assert 480/480 variant checks, but no Protocol 2 construction receipt accepts those variant records | candidate validation met; construction not met |
| Candidate validation receipt | Exact non-secret receipt derived from a safe snapshot | The [signed Protocol 2 receipt](receipts/candidate-validation-v2/) binds the private snapshot's aggregate shape, exact merged validator commit, approved verifier, 120 canaries, and 120/120 contained validations without exposing private scenario material | met for candidate validation only |
| Sealed scored corpus | 120, 24 per family | Candidate is not Protocol 2 accepted, piloted, frozen, or sealed | not met |
| Candidate custody | Inventory, canaries, access-log root, freeze receipt | The public candidate receipt binds 120 canaries and the cooperative access-log root; the owner-only source remains external, the hash chain is not kernel-enforced or independently anchored, and no freeze receipt exists | partial; release gate not met |
| Machine scenario review | Two bound reviews across two providers per scored scenario | Frozen veto contract exists; no accepted 120-scenario review matrix exists | mechanism met; evidence not met |
| Resolution variants | Two honest and two cheat variants per scenario, each artifact-bound | Candidate authoring checks exist; Protocol 2 artifact receipts are not yet accepted | partial; release gate not met |
| Agent QA | Five attempts per scenario across two configurations and two providers | No accepted scored-corpus QA matrix exists | not met |
| Blind agent solves | Six deterministic scenarios per family, two reference-isolated solvers across two providers/configurations | No accepted solve records exist | not met |
| Verification-image supply chain | Signed exact Dockerfile/hashed-lock inventory plus ordered OCI manifest/config identities keyed by target platform, enforced before verifier execution | Protocol 2 policy names both Docker-store identity representations from byte-identical clean exports for linux/amd64 and linux/arm64; claim remains bounded to Docker daemon/admin observations | mechanism met |
| Agent-image supply chain | Signed exact source/attestation policy for every networked agent image that executes sealed prompts | Agent image IDs are recorded, but no signed source or attestation allowlist approves their executable bytes | **HOLD; not implemented** |
| Credential isolation for sealed execution | Raw provider credentials remain outside the agent container; provider-allowlisted egress broker and exact projection/config receipt are mechanically bound | Closed Codex/OpenAI and Claude Code/Anthropic routes now use an external raw-credential broker, opaque lease plus signed routing projection, an isolated IPv4 agent bridge with no host gateway or IPv6, and a separate fresh broker-only IPv4 NAT bridge instead of Docker's shared default bridge. Loaded config bytes, effective destination/test-mode readiness, bounded connections, exact source/image/config/destination/projection/runtime receipts, and raw plus encoded credential scans across final argv, workdir, image metadata, and final rootfs are bound; signed prohibited path suffixes, nonempty config homes, or cleanup drift fail closed. Adversarial tests use synthetic credentials and local fake providers; no sealed/live run is claimed | mechanism met for two routes; evidence not run; third route requires a newly signed policy for baseline |
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

No live sealed review, QA, blind solve, pilot, baseline, or reproduction is authorized while
the agent-image supply-chain gate remains open. The signed verification-image policy and the
credential broker's immutable image/source checks do not approve the executable bytes in the
networked agent image. Those bytes still need their own signed, mechanically verified source
or attestation allowlist.

The ordinary direct `api_key_env` and copied `credential_mount` paths remain development
features only and Protocol 2 rejects them. The sealed path now keeps the raw provider
credential in a separate broker container; the agent receives only a fixed broker base URL
projection and opaque per-invocation lease on a fresh internal network. Its isolated IPv4
bridge has no host gateway or IPv6. The broker's second attachment is a fresh broker-only
IPv4 NAT bridge, never the shared default bridge. Docker's embedded DNS can resolve the broker alias, while
upstream DNS is loopback-only with root search and bounded retries; inherited image
healthchecks are disabled. Codex receives the route only through the signed
`openai_base_url` CLI override, never `OPENAI_BASE_URL`; Claude Code uses
`ANTHROPIC_BASE_URL`. Exact policy, broker configuration/source/image, destinations,
projection, Docker runtime, and command/environment/mount/network inventories are bound into
non-secret evidence. Prelaunch rejects raw, hex, standard or URL-safe Base64, and
percent-encoded credentials in final argv, workdir paths/links/files, image metadata, or the
exported final rootfs, as well as signed prohibited credential-path suffixes and a nonempty
declared or default agent config home. Runtime identities, audit, and cleanup are also bound.
Unsupported provider routes fail before the agent starts. Because the publication baseline
requires three providers and only OpenAI and Anthropic routes are currently defined, a third
route remains required even after the agent-image HOLD is closed. No sealed or live execution
is claimed by this mechanism-only status.

Run `stinger benchmark release-check benchmark/candidate-submission.yaml` for the
machine-readable current blocker list. A non-zero exit is the expected truthful result.
