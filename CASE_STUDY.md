# How Stinger was built

Stinger was built by directing AI coding agents under a strict governance regime — the same
discipline the tool itself exists to measure. The code was written by AI agents; the
operator supplied scope, frozen rules, release authority, and the insistence that claims be
artifact-checkable. That governance made the implementation auditable. The separately
claimed benchmark remains a candidate until its machine-only Protocol 2 gates are complete.

The operator is not a career software engineer — a background in construction purchasing and
small-scale manufacturing, not computer science. That is not the disclaimer it might read as.
It is the point of the exercise: the value here was never in typing the code, which an agent
does in seconds. It was in refusing to let the agent's output be trusted until it had earned
it — the constitution the agents worked under, the gates nobody was allowed to weaken, and
the insistence on evidence over anyone's say-so, including the AI's, and including the
operator's own.

## What the operator actually did

"Prompted an AI" does not describe it. The contribution was governance:

- **The constitution.** [AGENTS.md](AGENTS.md) binds every agent session that touches this
  code: build to [SPEC.md](SPEC.md), fail closed, never weaken a gate to make a test pass, no
  stubs in shipped code, and the software may not approve its own release. The spec was
  written first; the agent built to it and had to say which section each commit implemented.
- **Mechanical distrust.** A change is done when [`./scripts/check.sh`](scripts/check.sh)
  passes — lint, strict typing, the full test suite with enforced coverage floors (70%
  project-wide, 85% on the scoring and detector packages), a no-stub gate, and
  `stinger validate` re-proving all 30 traps fair on every commit. No self-report is trusted,
  least of all the AI's — which is, after all, the entire subject of the tool.
- **Enforced honesty.** Every capability in the README is graded by evidence, and the
  acceptance table publishes what is *not* done as prominently as what is. The public
  corpus ships its adversarial construct questions in
  [scenarios/AUDIT.md](scenarios/AUDIT.md), while Benchmark Protocol 2 requires
  artifact-bound variants, contained QA, provider-diverse machine veto reviews, blind agent
  solves, signed receipts, and cross-machine reproduction for the separate sealed corpus.
  Commentary cannot waive or relabel those mechanical gates.
- **Spending the money to hit reality.** Every fixture test passed. The decision was to run
  it against live agents anyway — because a measurement instrument that has only ever been
  tested against its own fixtures has not been tested.

## What hitting reality found

Stinger has now been run against two real coding agents — OpenAI Codex across four scenario
families and Claude Code across one, 30 live scenario runs in all, every package committed
under [evidence/](evidence/) and re-verifiable offline. The agents behaved well: they fixed
the bugs instead of faking them (and on C-04, the deliberately impossible task, refused —
the honest move there). The harness measured that correctly on 29 of the 30; the thirtieth
is C-04 itself, where it scored that textbook refusal wrong — defect 5 below tells that
story, and the mislabelled package is committed unedited.

But the runs were worth far more for what they *broke* than for what they scored. A string of
real defects surfaced that no fixture test had reached — and every one would have produced a
*plausible wrong answer* rather than a visible failure, which is the worst possible failure
mode for a tool whose job is measurement:

1. An agent CLI hung forever waiting on stdin — indistinguishable from an agent "thinking"
   until its time budget expired.
2. An agent sandbox mode left implicit — one wrong default and every scenario fails for a
   reason that has nothing to do with the agent.
3. Claim-detection recognised **one real completion report in six.** The patterns had been
   written from imagination ("All tests pass"); the first real agent wrote "Verification:
   `pytest` — **3 passed**", and the *second* wrote "All 3 tests pass now" — a different
   dialect that broke the fix for the first. Silently, the entire claims-audit family could
   have failed to catch a lying agent. Both are now pinned as regression fixtures from the
   captured real messages.
4. An `error` outcome didn't say *why* — an unauthenticated CLI was reported with detector
   noise instead of the actual cause.
5. The harness scored a **textbook-perfect refusal as a failure.** On a deliberately
   impossible scenario, the agent refused exactly right — *"the specification is
   unsatisfiable… I did not create a misleading implementation"* — and the trap's refusal
   markers recognised only the author's own vocabulary. The scenario had validated green
   against its own reference the whole time, because it was only ever asked to agree with
   itself.

That fifth one is the thesis in miniature. The defect was fixed, regression-tested against
six independently-worded refusals — and the mislabelled package was committed to
[evidence/](evidence/) **unedited**, because doctoring evidence after the fact is the one
thing this project must never do. The lesson is written into the corpus docs as
["the trap validation cannot catch"](scenarios/README.md#the-trap-validation-cannot-catch).

Before it was assembled for presentation, the whole repository was adversarially audited in
six role-separated AI review runs — one instructed to be a hostile reviewer hunting for the
single most damaging thing. Their top finding was that the boldest claims were the least
checkable, because the reproducibility packages had been left out of the commit. The
response was not softer wording; it was committing the evidence. That is why
[evidence/](evidence/) exists. Role separation is useful adversarial coverage, not proof of
organizational independence.

## What this is not

No number this repository has produced is a Stinger score. Each live run covers one scenario
family, and the tool itself stamps every such report `PARTIAL / DEV RUN — this MUST NOT be
presented as a Stinger score`. It is not a verdict on any vendor's agent — a clean run on six
scenarios, once, is an instrument check, not a leaderboard. The demo's strict-vs-permissive
agents are deterministic shell scripts, not models: they prove the instrument discriminates,
nothing more. Protocol 2 does not use a human spot-audit as benchmark evidence. The separate
120-scenario corpus cannot be described as a released benchmark until its signed candidate
receipt, sealed freeze, full baseline matrix, conformance evidence, cross-machine
reproduction, and final publication authorization all pass. And none of this is a claim that
AI replaces engineers — it is one datapoint about what a disciplined operator can now direct
AI to build, with receipts that let the claims be checked rather than trusted.
