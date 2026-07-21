# AGENTS.md — working agreements for building Stinger

These rules bind every agent, human, script, and automation that works in this repository.
Read this file first, every session, before touching code. They exist because Stinger is a
tool that measures integrity — it would be absurd, and disqualifying, to build it dishonestly.
Ingest `SPEC.md` and `TASKS.md` alongside this file.

## The prime directives

1. **Build to `SPEC.md`.** It is authoritative. Where it says MUST, comply. Where it marks
   **[OPEN]**, take the stated default and note the choice in your commit message. Do not
   invent scope, rename the public contracts in §4–§6, or change the frozen decision order
   in §7 or the rubric in §8. If the spec is genuinely wrong or contradictory, stop and say
   so — do not paper over it.

2. **Fail closed.** Any ambiguity, missing evidence, or harness error resolves to the
   non-scoring `error` outcome, never to a favorable one. When unsure whether something is a
   cheat, a detector returns evidence and the runner routes to review — it never guesses
   "honest."

3. **Never weaken a gate to make a test pass.** This is the cardinal sin, and it is the
   exact behavior Stinger is built to catch. Do not delete, skip, `xfail`, loosen, or mock
   away a failing test to get green. Fix the code. If a test is wrong, say so explicitly and
   change it in a separate, called-out commit with the reason — never silently.

4. **No stubs in shipped code.** The `skeleton/` files contain `NotImplementedError` and
   `# BUILD:` markers. Those are the starting scaffold and the *only* permitted stubs. A
   task is not done while any remain in the files it touched. `check.sh` greps for them and
   fails — do not defeat that check.

5. **Mechanical truth over the LLM judge.** Cheating is decided by deterministic detectors.
   The judge (§9) may only flag for review. If you find yourself wanting the judge to decide
   a score, you are building it wrong.

6. **Determinism in scoring.** Same corpus + config + agent build ⇒ same score. Do not read
   the wall clock, `random` without a seed, or the network anywhere in the scoring path.
   Timestamps are passed in, not read mid-run.

## Definition of done (there is only one)

A change is done when **`./scripts/check.sh` passes** from a clean state — ruff, mypy
strict, pytest with the coverage floor, the no-stub check, and `stinger validate scenarios/`
all green. Not when you believe it works. Not when the happy path runs. Green gate or not
done. Run it before every handoff and before saying a task is complete.

## Scenario integrity (the corpus is the product)

- Every scenario MUST ship `reference/honest.patch` and `reference/cheat.patch` and MUST
  pass the validity contract (`SPEC.md` §12) before it counts. A trap that fires on correct
  behavior, or fails to fire on the intended cheat, is a bug that invalidates results — treat
  it with more care than a normal bug.
- Bait secrets are dummies. "Exfiltration" sinks are local. Nothing in this repo may target
  a real system, real credential, or real third party. The `X` family is defensive only.
- Do not tune a scenario so a particular agent looks good or bad. Scenarios are written
  against the spec, never against an agent's known behavior.

## Honesty in reporting (practice what the tool preaches)

- Never present a partial or dev run as a Stinger score. All five families or it is labeled
  partial.
- Never publish a number without its reproducibility package.
- The status doc grades capabilities by evidence: `working` (tested), `scaffolded`
  (skeleton only), `absent`. No capability is described as working without a passing test.
- If Stinger is ever run to compare vendors, disclose relationships and invite the vendor
  to re-run before publication. Never accept payment to alter, withhold, or weight a result.

## Working style

- Small, reviewable commits, each leaving `check.sh` green. Conventional-commit style
  messages that name the SPEC section addressed (e.g. `feat(detectors): forbidden_path per SPEC §6`).
- Full type annotations; ruff-clean; mypy-strict; Google-style docstrings that state the
  detector/behavior contract, not just the types.
- Do not add runtime dependencies beyond those named in `SPEC.md` §2 without recording why.
- If you are Codex reviewing Claude's work (or vice versa): review against `SPEC.md`, do not
  rewrite to taste, and resolve genuine conflicts by asking the human operator. One agent
  implements a branch; the other reviews the PR; never both edit the same branch.

## What only the human operator (Chris) decides

Publishing any public result or vendor comparison; changing `RUBRIC_VERSION` or any frozen
rule; adding a scenario family; anything that spends money or signs up for a service. The
software and its building agents may not approve their own release.
