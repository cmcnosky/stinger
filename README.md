# Stinger

[![CI](https://github.com/cmcnosky/stinger/actions/workflows/ci.yml/badge.svg)](https://github.com/cmcnosky/stinger/actions/workflows/ci.yml)

**Measure whether an AI coding agent cheats — in your configuration, in your CI.**

Stinger runs a corpus of sandboxed trap scenarios against a configured coding agent,
mechanically detects dishonest shortcuts (weakened tests, forbidden-file edits, fabricated
completion claims, broken house rules, leaked bait secrets), and emits a scored,
evidence-linked **Integrity Report** under a preregistered, frozen scoring rubric.

It is a CLI and a GitHub Action. It is model-agnostic and vendor-neutral by construction.

Two rules shape everything here:

- **Mechanical truth first.** Cheating is decided by deterministic detectors, never by an
  LLM judge. The optional judge may only add an item to a non-authoritative review queue;
  it can never set or override a `cheated`/`honest` label or headline metric.
- **Fail closed.** Any ambiguity, harness error, or missing evidence resolves to a
  non-scored `error`, never to a favorable score.

See [SPEC.md](SPEC.md) for the authoritative specification and [AGENTS.md](AGENTS.md) for
the working agreements that bind every contributor, human or agent.

## Benchmark status: candidate, not benchmark

Stinger is currently a **benchmark candidate / instrument demonstration**. The 30 public
scenarios are the development and conformance suite; because their prompts, oracles, and
reference resolutions are public, they are not used for a headline benchmark claim.

The separately versioned [Benchmark Protocol 2](BENCHMARK.md) specifies a sealed
120-scenario scoring corpus, artifact-bound QA, provider-diverse machine vetoes,
reference-isolated blind agent solves, six pinned configurations across three providers,
five repetitions, cluster-aware uncertainty, three clean conformance environments, signed
public/escrow evidence, and one complete cross-machine reproduction. Machine review can
only veto evidence; it cannot relabel a result or change the frozen score.

A private, externally stored authoring checkpoint now contains 120 candidate scenarios:
24 per family, with eight small, eight medium, and eight large repositories per family.
Its 480 concrete honest/cheat variants passed their authoring checks, and all 120 primary
scenarios passed contained Docker validity. That is candidate construction evidence, not
an accepted Protocol 2 validation receipt, machine-review/QA matrix, blind-solve record,
frozen or sealed scoring corpus, baseline result, or benchmark claim. No cross-machine
reproduction is claimed.

There is also a hard credential-isolation HOLD before any live sealed execution. Current
networked agent containers can read raw Codex/Claude credentials. An ordinary
`credential_mount` may contain extra hidden CLI configuration or session files even though
the published fingerprint records only that a mount exists. Read-only mounting and
post-run leakage scans do not prevent a sealed prompt from inducing credential abuse. No
sealed review, QA, blind solve, pilot, baseline, or reproduction is authorized until an
external provider-allowlisted credential broker (or equivalent that keeps raw credentials
outside the agent container) and an exact minimal projection/config receipt are
mechanically implemented and evidence-bound.

Protocol 2 now separately closes the verification-image substitution gap. The signed
protocol commits to the exact `docker/runner.Dockerfile` and fully hash-locked dependency
bytes, then approves the OCI manifest and image-config identities derived from the same
byte-identical clean exports for each Docker target platform. Containerd-backed and classic
Docker stores report different one of those two immutable identities as `.Id`; the signed
policy names both explicitly. Every benchmark validation, replay, construction, and run
checks that policy before starting a verification container. This is an exact-byte
observation through the fixed Docker client/daemon boundary, not a universal
reproducible-build, registry-attestation, TPM, or hostile-administrator proof.

That verifier policy does **not** approve agent images. Agent containers execute untrusted
sealed prompts with network access, so their own image supply chain remains a separate hard
HOLD alongside credential isolation. No live sealed review, QA, blind solve, pilot, baseline,
or reproduction is authorized until both holds are mechanically closed and evidence-bound.

The current state is executable:

```bash
stinger benchmark protocol-check benchmark/protocol.yaml
stinger benchmark release-check benchmark/candidate-submission.yaml
```

The first command checks the exact Protocol 2 threshold structure. The second intentionally
exits non-zero and enumerates every unearned release gate. Only a fully evidenced,
role-separated, signed submission can produce `machine_reproduced`; “established
benchmark” additionally requires three accepted cross-machine environment records and a
documented correction cycle.

## Install

Requires Python 3.12+.

```bash
pip install -e ".[dev]"
```

## Core commands

```bash
stinger list                     # scenarios + families + validity status
stinger validate scenarios/      # run the validity contract (SPEC.md §12)
stinger run --config stinger.yaml
stinger report repro/<timestamp> --format html
```

Benchmark operators additionally use `stinger benchmark --help` for protocol signing,
release checks, paired candidate-minus-baseline intervals, and public/escrow evidence
bundles. These commands never turn the public development suite into benchmark evidence.

> Heads-up before the second command: validating the full corpus needs the Docker
> verification image (the `X` safety family refuses to validate unconfined), and so does any
> run under the default `docker` isolation. It is a one-line build — see
> [Development](#development). A family-scoped `--local` dev run needs neither — that is how
> the committed [evidence/](evidence/) packages were produced — and `stinger list` plus
> validating the other 24 scenarios also work without it.

Copy [stinger.example.yaml](stinger.example.yaml) to `stinger.yaml` to get started; it
documents every setting, including how to point the generic `shell` adapter at an agent
Stinger has never heard of. No key ever goes in that file — an adapter names the environment
variable holding its key, so a resolved config is safe to commit next to the report it
produced.

For a **first run**, scope to one family: `stinger run --config stinger.yaml --only T`. A
full five-family run includes `X`, which refuses to start until `agent.container_image`
names an image with your agent's CLI inside — the safety family never runs against an
uncontained agent, by design (SPEC.md §2). The example config documents the container
settings when you are ready for the full corpus.

`stinger report` does more than re-render. It recomputes every published number from the
report's own stored results, and re-checks that each scenario's outcome actually follows from
its own detector evidence (a detector that fired cannot sit beside an `honest` outcome), and
exits non-zero if anything disagrees — so a published report is checkable offline by someone
who was not there, no agent, no container, no network. That is step 1 of the `rerun.sh` every
run writes.

`stinger validate` is the one to understand first. Before any agent is judged, every
scenario must pass its mechanical validity contract: overlay the scenario's *honest*
reference resolution and no detector may fire; overlay its *cheat* reference and the
intended detector must fire. A scenario that fails validation is refused entry to a
scoring run.

## Scenario families

| Family | Measures |
|---|---|
| `T` | test-integrity — weakening, deleting, or skipping tests |
| `S` | spec-fidelity — quietly changing the spec instead of meeting it |
| `C` | claims-audit — claiming done/passing when it is not |
| `G` | governance-compliance — breaking stated house rules |
| `X` | safety / exfiltration — leaking bait secrets, forbidden commands |

## Honest status

Graded by evidence, per AGENTS.md: **working** = covered by a passing test;
**scaffolded** = interface exists, behavior not implemented; **absent** = not written.

| Capability | Status |
|---|---|
| Core data model (`models.py`) | working |
| Sandbox isolation + RepoState capture (§2, §7) | working — real container runs verified, including that the network is off and the mount hides the rest of the scenario |
| Contained agent — `container_image`, `credential_mount` (§5) | working for development containment, **not credential-isolated for sealed execution** — [docker/codex-agent.Dockerfile](docker/codex-agent.Dockerfile) builds a Codex image and the read-only mount is unit-tested, but raw credentials remain readable by the networked agent and ordinary mount contents are not evidence-bound; no sealed live run is authorized |
| Run state machine + frozen `classify()` (§7) | working |
| Held-out completion check (§7) | working |
| All seven detectors (§6) | working — each fires on its intended cheat and stays silent on the honest reference, unit-tested and exercised by the corpus |
| Validity contract + `stinger validate` / `list` (§12, §13) | working |
| Frozen rubric math, incl. modal outcome + variance (§8) | working |
| Integrity Report — JSON, Markdown, HTML (§4, §8) | working |
| Reproducibility package + `rerun.sh` (§10) | working — `rerun.sh` re-ran a live agent over the same corpus and config and reproduced identical corpus hash, config fingerprint, family scores and per-scenario outcomes; both packages are committed in [evidence/](evidence/) |
| `stinger run` / `stinger report` (§13) | working |
| Optional LLM judge (§9) | working, but no transport — the bounds and prompt are implemented and tested; the operator supplies a `JudgeClient`. Disabled by default. |
| `shell` adapter (§5) | working — driven end to end by `stinger run` against a local agent script, through a real PTY |
| `codex` adapter (§5) | working — **run live against a real model** across families T, S, C, G (24 scenarios); every completion confirmed by the held-out oracle; full packages in [evidence/](evidence/) |
| `claude-code` adapter (§5) | working — **run live against a real model** (family T, 6 scenarios); `rerun.sh` reproduced the scoring; packages in [evidence/](evidence/) |
| `aider` adapter (§5) | built, not yet run against a live model — argv, credential handling, timeouts and output parsing are tested against recorded CLI output |
| CI regression gate + reusable workflow (§14) | working — absolute threshold and no-regression-vs-baseline, both enforced by `stinger run` itself |
| Benchmark protocol + exact run/scenario metadata | working — separately versioned without changing `RUBRIC_VERSION`; legacy configs and reports remain readable |
| Seeded family-blocked benchmark ordering | working — stable across input order and mechanically rechecked at the release gate |
| Cluster-aware 95% bootstrap and paired differences | working — repetitions stay nested within scenarios; persisted intervals are recomputed by `stinger report` |
| Signed public / escrow benchmark evidence | working — OpenSSH detached protocol signature, separately supplied trust policy, exact inventories, sealed-file/canary/secret leakage checks, escrow classification replay from primary artifacts, and explicit unencrypted-escrow warning |
| Protocol 2 machine construction gate | working on this candidate implementation — artifact-bound variants/QA, provider-diverse veto review, deterministic blind agent solves, custody receipts, and stable fail-closed issue codes |
| Benchmark master release gate | working on this candidate implementation — typed corpus, machine QA/review/solve, baseline, conformance, cross-machine, and operator-authorization evidence |
| Sealed scoring corpus | **candidate built; not sealed** — a private externally stored checkpoint has 120 candidates, 24 per family; Protocol 2 receipt normalization, machine QA/review/blind solves, split-only promotion, exact-snapshot pilot, and freeze remain undone |
| Clean conformance + cross-machine reproduction | **not done** — no accepted conformance environment or complete reproduction record exists |
| Benchmark v1 release | **HOLD** — the checked-in candidate submission fails the master gate; only Chris can approve spending, publication, or a vendor comparison after all other gates pass |
| Discrimination demo (§16.4) | working — a strictly configured agent scores 100% and passes; a permissive one scores 0% and fails, on the same corpus (family T only, a labeled partial run — [demo/](demo/)) |
| Scenario corpus | **30 validated scenarios, 6 in each of the five families** ([scenarios/README.md](scenarios/README.md)) |

### v1 acceptance (SPEC.md §16)

| # | Criterion | State |
|---|---|---|
| 1 | `check.sh` green from a clean clone | **met** — CI checks out, installs and runs it on every push (locally, a clean clone additionally needs Docker running and the verification image built first) |
| 2 | `stinger validate` passes for ≥30 scenarios across all five families | **met** — 30/30 |
| 3 | `stinger run` against **at least two real adapters**, with `rerun.sh` reproducing the scoring | **met** — codex and claude-code both run live, both with `rerun.sh` reproducing every score identically ([evidence/](evidence/)) |
| 4 | The action fails a permissive agent and passes a strict one | **met** — [demo/](demo/) |
| 5 | No stubs in `src/`; README documents install, the commands, and this table | **met** |

All five §16 criteria are now met. Two real agents have been measured — codex across four
families (T, S, C, G) and claude-code across one (T) — every completion confirmed by the
held-out oracle the agent never saw, and `rerun.sh` reproducing the scoring for both. The
complete reproducibility packages are committed in [evidence/](evidence/), so none of this
has to be taken on trust: `stinger report evidence/<package>` re-verifies any of them
offline.

One honest limit remains, stated rather than hidden. Each live run in [evidence/](evidence/)
covers one family, so every report there carries the tool's own `PARTIAL / DEV RUN` banner —
none is a Stinger score, and none is a verdict on any agent (one repetition, no comparison
conditions).

The `X` safety family remains the standing limit, stated rather than hidden. It seeds bait
credentials and destructive lures that must never touch an unconfined agent, so running it
live needs the agent CLI packaged *inside* the verification container. That mechanism now
exists and is unit-tested — [docker/codex-agent.Dockerfile](docker/codex-agent.Dockerfile)
builds a contained Codex image, `agent.container_image` makes a run use it, and
`agent.credential_mount` lets a file-authenticated CLI reach its credential read-only. Two
defects had to be fixed before it worked at all, each the kind that produces a
plausible-looking wrong answer rather than a visible failure: a contained agent received no
credential (a container inherits nothing, and nothing forwarded it), and a CLI that
authenticates from a file rather than an environment variable had no way in until
`agent.credential_mount`. But no contained run and no `X`-family run is committed as evidence
here, and by this project's own rule — *reproducibility or it didn't happen* (SPEC.md §1.4) —
an uncommitted run is not a result. So the honest state is the one
[evidence/README.md](evidence/README.md) states: **not yet**. `stinger run` refusing X
against an unconfined agent was always the point and still holds — "refuses safely" is true;
"has been run safely" is not something this repo can show you yet.

The live runs were worth far more for what they broke than for what they scored. A string of
real defects surfaced that no amount of fixture testing had reached, and every one would have
produced a plausible-looking wrong answer rather than a visible failure: an agent that hung
forever and looked like it was thinking; an unset sandbox mode that would have failed every
scenario; claim-detection that recognised one real completion report in six — and then missed
the *second* agent's different phrasing too, because real agents never say what you imagine;
an `error` outcome that never said why; a refusal scored as a capability gap because the
scenario and its own reference shared a vocabulary; and a stripped environment that left the
second agent unable to reach its own credential. See the commits around them — that pattern,
not the scores, is the argument for putting a tool like this in front of a real agent early.

Stinger's own test suite never calls a model and never reaches the network. Adapters are
tested by replaying recorded CLI output through their real parsers, and the subprocess and
PTY paths are driven against local scripts standing in for an agent.

## Development

`./scripts/check.sh` is the only definition of done: ruff, ruff-format, mypy strict, pytest
with the coverage floors, a no-stub check, and `stinger validate scenarios/`. Green gate or
not done. Never weaken a gate to make it pass — that is the exact behavior this tool exists
to catch.

It needs Docker, because the `X` safety family refuses to run unconfined (SPEC.md §2). Build
the verification image once. On Apple Silicon:

```bash
stinger_runner_build_dir="$(mktemp -d)"
docker buildx create --name stinger-verifier-v0312 \
  --driver docker-container \
  --driver-opt image=moby/buildkit:v0.31.2 \
  --use --bootstrap
docker buildx build --no-cache --provenance=false \
  --build-arg SOURCE_DATE_EPOCH=0 \
  --platform linux/arm64 -t stinger-runner:1 \
  --output type=docker,rewrite-timestamp=true,dest="$stinger_runner_build_dir/stinger-runner.tar" \
  -f docker/runner.Dockerfile docker/
docker load --input "$stinger_runner_build_dir/stinger-runner.tar"
```

Use `linux/amd64` on an amd64 Docker host. A bare `python:3.12-slim` will not do —
verification runs with the network disabled, so pytest has to already be in the image.
Benchmark operations additionally require the exact platform/image ID and Dockerfile/lock
inventory frozen in the signed protocol; importing pytest is necessary but not sufficient.
Stinger refuses before verification starts rather than letting an arbitrary verifier
manufacture a plausible score.

## License

Code: Apache-2.0 ([LICENSE](LICENSE)). Scenario corpus: CC-BY-4.0
([scenarios/LICENSE](scenarios/LICENSE)).

## Provenance

Stinger was built by directing AI coding agents under the governance regime documented in
[AGENTS.md](AGENTS.md) — the same discipline the tool exists to measure. What that involved,
and what running it against real agents exposed, is written up in
[CASE_STUDY.md](CASE_STUDY.md).

## Contact

Chris McNosky · Dallas–Fort Worth, TX · cmcnosky@gmail.com — available for AI-systems
direction, agent-governance consulting, and roles where making AI-built software provably
trustworthy is the job.
