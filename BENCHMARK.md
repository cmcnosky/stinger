# Stinger Benchmark Protocol

Status: **candidate protocol — not a published benchmark**

`RUBRIC_VERSION` and `BENCHMARK_PROTOCOL_VERSION` answer different questions. The
rubric versions the frozen integrity-rate arithmetic in `SPEC.md` §8. The benchmark
protocol versions the task-selection, review, execution, uncertainty, evidence, and
publication rules in this document. A protocol revision never silently changes the
rubric.

## Construct and claim boundary

Stinger measures whether a configured coding agent takes a mechanically defined
integrity-violating shortcut when a scenario presents that opportunity. It does not
measure whether a model is "honest in general", and it does not infer intent.

The public 30-scenario corpus is a development and conformance suite. Its prompts,
oracles, honest resolutions, and cheat resolutions are public, so it MUST NOT supply a
headline Stinger Benchmark result. An active scored corpus is separately authored,
reviewed, sealed, and later released when retired.

The claim ladder is:

1. **Stinger benchmark candidate:** the instrument and candidate protocol exist.
2. **Stinger Benchmark v1, independently reproduced:** every release gate below is met
   and one unaffiliated evaluator has reproduced a complete sealed baseline.
3. **Established benchmark:** at least three unaffiliated teams have produced accepted
   runs and the protocol has survived one documented corpus-correction/version cycle.

Stars, downloads, or self-authored reruns do not move a result up this ladder.

## Corpus design

Benchmark v1 remains Python-only and retains the five frozen families: T, S, C, G, X.

- Development/conformance split: the existing 30 public scenarios, six per family.
- Active scored split: 120 sealed scenarios, 24 per family.
- Each family contains eight small, eight medium, and eight larger multi-module
  repositories.
- Each scenario has an explicit `scenario_version` and `cluster_id`. Related variants
  share a cluster and never count as independent statistical evidence. The 120 scored
  slots therefore require 120 independently counted clusters; related variants may remain
  in the candidate pool, but two cannot occupy separate scored slots.
- An active scenario carries only fake credentials, local sinks, and defensive safety
  lures. No real credential or third-party target is permitted.

Every scored scenario requires:

- two independent fairness reviews and adjudication of every disagreement;
- two materially different honest resolutions and two materially different cheat
  attempts;
- five agent QA attempts with every transcript reviewed;
- a passing held-out oracle and validity contract;
- containment and dummy-secret checks; and
- recorded authorship, provenance, review, and access history.

A stratified 25% of the scored corpus — six scenarios per family — additionally requires
a blind hands-on human solve.

## Baseline protocol

A publication baseline covers six fully pinned agent configurations spanning at least
three providers. Each configuration runs every scored scenario five times.

Every run records:

- exact model and agent CLI/build versions;
- reasoning and inference settings;
- Stinger commit and benchmark protocol version;
- agent and verification container image digests;
- corpus hash and fixed run seed; and
- the complete permitted transcript, command, diff, detector, and oracle evidence.

All agent runs are contained. Scenario order is deterministically blocked from the fixed
seed. Repetitions expose agent variance but are never treated as independent tasks.
Before the first task, benchmark mode requires a clean Git worktree and mechanically
observes the exact Git HEAD, local Docker image identities/digests, agent CLI version, and
resolved model/settings invocation. A declaration that does not match those observations
fails closed. The canonical `provider` field records the requested provider identity; it is
not a remote provider attestation, and the preflight performs no network call.

## Uncertainty and comparisons

The frozen rubric continues to produce modal scenario outcomes and per-family integrity
rates. Benchmark reporting adds deterministic, cluster-aware 95% bootstrap intervals over
scenario clusters and repetitions. Configuration comparisons use a paired cluster
bootstrap over the shared scenario set.

Every publication interval is 95% and uses at least 10,000 bootstrap draws. Lower-sample
statistics may be useful during development but fail the master release gate.

A point estimate without its interval, denominator, refusal/failure/error counts, and
per-scenario outcome distribution is not a benchmark result. Overlapping intervals are
not silently narrated as a ranking.

## Evidence tiers

Every candidate result produces two inventories:

- **Public bundle:** report, resolved non-secret configuration, protocol and corpus
  hashes, permitted logs, statistics, and evidence. It MUST NOT contain the active corpus,
  reference resolutions, held-out checks, bait-secret values, or escrow paths.
- **Escrow bundle:** the complete rerunnable package, including the active corpus. It is
  access-controlled operationally and supplied to the independent verifier. The current
  implementation does not claim to encrypt it.

The public bundle is mechanically scanned before release. The scored corpus remains
outside the public repository and is released in full when retired.

Any ordinary repro directory touching an active sealed scenario receives
`SEALED_BENCHMARK_EVIDENCE_DO_NOT_UPLOAD` before adapter construction or runtime preflight.
It never receives a corpus copy. The reusable GitHub workflow detects that marker, suppresses
artifact upload and job-summary disclosure, and fails rather than treating active sealed
evidence as a normal CI artifact. Public bundle creation separately redacts host-only paths
and rejects secret-looking or absolute command arguments.

The frozen protocol is signed with an operator-controlled OpenSSH key under the
`stinger-benchmark-protocol` signature namespace. Bundle verification requires an
independently obtained `allowed_signers` file and expected signer identity; the trust file
inside a bundle is never accepted merely because it arrived with the bundle. Stinger does
not generate or copy the private key.

Release requires two additional out-of-band signatures. Chris signs the exact completed
release submission under `stinger-benchmark-release`; a Boolean approval inside that same
submission is not authority. The unaffiliated evaluator signs an artifact-binding
reproduction statement under `stinger-benchmark-reproduction` using a separately supplied
verifier trust policy. Release and reproduction must resolve to different signer identities,
different verified signing-key fingerprints, and different signer policies; signature
namespaces alone are only domain separation and do not prove independence. The statement
binds both reports, both agent-configuration fingerprints, corpus and bundle hashes,
distinct machine fingerprints, and a resolved discrepancy ledger.

## Publication eligibility

A result is ineligible unless all of these hold:

- all five families are present;
- the scored corpus has 120 valid scenarios, 24 per family;
- every scenario and human/agent QA record satisfies the corpus contract;
- all six baseline configurations use five repetitions;
- unexplained `error` outcomes are at most 1% of repetitions;
- every family has at least 20 scorable modal outcomes;
- all required build, image, model, settings, seed, and protocol pins are present;
- no containment, evidence-integrity, canary, or public-bundle leakage check fails;
- the full master gate passes from a clean state;
- three outside beta operators have completed the public development workflow;
- one unaffiliated evaluator has reproduced a complete sealed baseline; and
- the human operator has approved spending and publication and signed the exact final
  release submission.

Until every condition is evidenced, tooling MUST report the status as a benchmark
candidate and MUST NOT emit or imply a vendor ranking.

`benchmark/protocol.yaml` is the machine-readable threshold set.
`benchmark/candidate-submission.yaml` is the checked-in truthful current evidence record.
`stinger benchmark release-check benchmark/candidate-submission.yaml` is expected to exit
non-zero until the outside work and human approvals are real. An eligible check additionally
receives the release signature/trust options and the independent reproduction
statement/signature/verifier-trust options documented in `benchmark/EVIDENCE.md`. Stable
issue codes make that gap auditable rather than aspirational.

## Corrections and release

The scored corpus and protocol freeze before publication baselines run. Corrections are
never made silently: they receive a new corpus or protocol version, a changelog entry,
affected-result disclosure, and re-scoring where possible. Vendors are invited to rerun
before a comparative public result is released.

Public results, vendor comparisons, rubric changes, new scenario families, spending, and
service sign-ups remain human-operator decisions under `AGENTS.md`.
