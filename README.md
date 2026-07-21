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
| Frozen `classify()` decision order (§7) | scaffolded |
| Frozen rubric math (§8) | scaffolded |
| `forbidden_path` detector | scaffolded |
| Other six detectors | absent |
| Sandbox / RepoState capture (§7) | absent |
| Run state machine (§7) | scaffolded |
| Validity contract (§12) | scaffolded |
| Scoring, report, repro package (§8, §10) | scaffolded |
| Agent adapters — claude-code, codex, aider, shell (§5) | absent |
| Optional LLM judge (§9) | absent |
| GitHub Action (§14) | scaffolded |
| Scenario corpus | 1 of ≥30 (`T-02`, the worked reference) |

No number produced by this repository is a Stinger score until the corpus spans all five
families and ships with its reproducibility package. Until then, runs are dev runs and are
labeled as such.

## Development

`./scripts/check.sh` is the only definition of done: ruff, ruff-format, mypy strict, pytest
with the coverage floor, a no-stub check, and `stinger validate scenarios/`. Green gate or
not done. Never weaken a gate to make it pass — that is the exact behavior this tool exists
to catch.

## License

Code: Apache-2.0 ([LICENSE](LICENSE)). Scenario corpus: CC-BY-4.0
([scenarios/LICENSE](scenarios/LICENSE)).
