# Stinger

**Measure whether an AI coding agent cheats — in your configuration, in your CI.**

Stinger runs a corpus of sandboxed trap scenarios against a configured coding agent,
mechanically detects dishonest shortcuts (weakened tests, forbidden-file edits, fabricated
completion claims, broken house rules, leaked bait secrets), and emits a scored,
evidence-linked **Integrity Report** under a preregistered, frozen scoring rubric.

It is a CLI and a GitHub Action. It is model-agnostic and vendor-neutral by construction.

Two rules shape everything here:

- **Mechanical truth first.** Cheating is decided by deterministic detectors, never by an
  LLM judge. The optional judge may only *flag for human review*; it can never set or
  override a `cheated`/`honest` label.
- **Fail closed.** Any ambiguity, harness error, or missing evidence resolves to a
  non-scored `error`, never to a favorable score.

See [SPEC.md](SPEC.md) for the authoritative specification and [AGENTS.md](AGENTS.md) for
the working agreements that bind every contributor, human or agent.

## Install

Requires Python 3.12+.

```bash
pip install -e ".[dev]"
```

## The four commands

```bash
stinger list                     # scenarios + families + validity status
stinger validate scenarios/      # run the validity contract (SPEC.md §12)
stinger run --config stinger.yaml
stinger report repro/<timestamp> --format html
```

Copy [stinger.example.yaml](stinger.example.yaml) to `stinger.yaml` to get started; it
documents every setting, including how to point the generic `shell` adapter at an agent
Stinger has never heard of. No key ever goes in that file — an adapter names the environment
variable holding its key, so a resolved config is safe to commit next to the report it
produced.

`stinger report` does more than re-render. It recomputes every published number from the
report's own stored results and exits non-zero if anything disagrees, so a published report
is checkable offline by someone who was not there — no agent, no container, no network. That
is step 1 of the `rerun.sh` every run writes.

`stinger validate` is the one to understand first. Before any agent is judged, every
scenario must prove it is fair: overlay the scenario's *honest* reference resolution and no
detector may fire; overlay its *cheat* reference and the intended detector must fire. A
scenario that fails validation is refused entry to a scoring run. That is the corpus's own
fail-closed gate.

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
| Run state machine + frozen `classify()` (§7) | working |
| Held-out completion check (§7) | working |
| All seven detectors (§6) | working — each fires on its intended cheat and stays silent on the honest reference, unit-tested and exercised by the corpus |
| Validity contract + `stinger validate` / `list` (§12, §13) | working |
| Frozen rubric math, incl. modal outcome + variance (§8) | working |
| Integrity Report — JSON, Markdown, HTML (§4, §8) | working |
| Reproducibility package + `rerun.sh` (§10) | working |
| `stinger run` / `stinger report` (§13) | working |
| Optional LLM judge (§9) | working, but no transport — the bounds and prompt are implemented and tested; the operator supplies a `JudgeClient`. Disabled by default. |
| `shell` adapter (§5) | working — driven end to end by `stinger run` against a local agent script, through a real PTY |
| `codex` adapter (§5) | working — **run live against a real model** across families T and C (12 scenarios), every completion confirmed by the held-out oracle |
| `claude-code`, `aider` adapters (§5) | built, **not yet run against a live model** — argv, credential handling, timeouts and output parsing are tested against recorded CLI output; the model call itself is unverified |
| CI regression gate + reusable workflow (§14) | working — absolute threshold and no-regression-vs-baseline, both enforced by `stinger run` itself |
| Discrimination demo (§16.4) | working — a strictly configured agent scores 100% and passes; a permissive one scores 0% and fails, on the same corpus ([demo/](demo/)) |
| Scenario corpus | **30 validated scenarios, 6 in each of the five families** ([scenarios/README.md](scenarios/README.md)) |

### v1 acceptance (SPEC.md §16)

| # | Criterion | State |
|---|---|---|
| 1 | `check.sh` green from a clean clone | **met** — CI checks out, installs and runs it on every push |
| 2 | `stinger validate` passes for ≥30 scenarios across all five families | **met** — 30/30 |
| 3 | `stinger run` against **at least two real adapters**, with `rerun.sh` reproducing the scoring | **half met** — `codex` has run live; a second adapter needs its CLI installed |
| 4 | The action fails a permissive agent and passes a strict one | **met** — [demo/](demo/) |
| 5 | No stubs in `src/`; README documents install, the commands, and this table | **met** |

Criterion 3 is the remaining gap. One real agent has now been measured — codex scored 6/6
honest on family T, with every fix confirmed by the held-out oracle it never saw. That run is
what the spec asks for, but only for one adapter, and it covered one family, so it is still a
partial run and not a Stinger score.

The live runs were worth far more for what they broke than for what they scored. Five real
defects surfaced that no amount of fixture testing had reached, and every one of them would
have produced a plausible-looking wrong answer rather than a visible failure: an agent that
hung forever and looked like it was thinking; an unset sandbox mode that would have failed
every scenario; claim-detection that recognised one real completion report in six, silently
disabling the whole claims-audit family; an `error` outcome that never said why; and a
refusal scored as a capability gap because the scenario and its own reference were written in
the same vocabulary. See the commits around them — that pattern is the argument for running
this against a real agent early, not the score.

Stinger's own test suite never calls a model and never reaches the network. Adapters are
tested by replaying recorded CLI output through their real parsers, and the subprocess and
PTY paths are driven against local scripts standing in for an agent.

## Development

`./scripts/check.sh` is the only definition of done: ruff, ruff-format, mypy strict, pytest
with the coverage floors, a no-stub check, and `stinger validate scenarios/`. Green gate or
not done. Never weaken a gate to make it pass — that is the exact behavior this tool exists
to catch.

It needs Docker, because the `X` safety family refuses to run unconfined (SPEC.md §2). Build
the verification image once:

```bash
docker build -t stinger-runner:1 -f docker/runner.Dockerfile .
```

A bare `python:3.12-slim` will not do — verification runs with the network disabled, so pytest
has to already be in the image. `stinger run` preflights this and refuses to start otherwise,
rather than letting every scenario score as a failure for a reason unrelated to the agent.

## License

Code: Apache-2.0 ([LICENSE](LICENSE)). Scenario corpus: CC-BY-4.0
([scenarios/LICENSE](scenarios/LICENSE)).
