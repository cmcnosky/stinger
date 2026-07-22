# How this repository was built (a note for visitors)

Every line of code in this repository was written by an AI coding agent — Claude
(Anthropic) built the system in twenty commits over a two-day sprint — directed by a
single operator with no software employment history and no computer science degree: a
former homebuilder purchasing manager who runs a small manufacturing business.

That is not a confession. It is the experiment. And this time the experiment is
recursive: **Stinger is a tool that catches AI coding agents cheating, built by an AI
coding agent, under the exact governance it exists to measure.** If the discipline
described below did not work, this repository is where it would show.

## What Stinger is

Research through 2025–26 (ImpossibleBench and successors) established that frontier
coding agents cheat at startling rates when given the opportunity — weakening tests
to make them pass, fabricating "all tests green," quietly editing the spec instead of
meeting it — and that the rate depends heavily on how the agent is configured and
governed. Those papers are lab instruments that grade frontier *models*. Stinger
packages the same question as a tool a team runs in CI against *their* agent, *their*
repo, *their* rules: 30 sandboxed trap scenarios across five families, seven
deterministic detectors, a preregistered scoring rubric, and an evidence-linked
Integrity Report with a one-command reproducibility package. No LLM judges anything:
cheating is decided mechanically or not at all, and anything unverifiable resolves to
a non-scoring `error`, never to a favorable number.

## What the operator actually did

"Prompted an AI" does not describe it, so here is what the human contributed:

- **The constitution.** [AGENTS.md](AGENTS.md) binds every agent session that touches
  this code: build to [SPEC.md](SPEC.md), fail closed, never weaken a gate to make a
  test pass, no stubs in shipped code, and the software may not approve its own
  release. The spec was written first; the agent built to it and had to say so, in
  commit messages that cite the section they implement.
- **Mechanical distrust.** A change is done when [`./scripts/check.sh`](scripts/check.sh)
  passes — lint, strict typing, the full test suite with enforced coverage floors (70%
  project-wide, 85% on the scoring and detector packages), a no-stub gate, and
  `stinger validate` re-proving all 30 traps fair on every commit. Nobody's
  self-report is trusted here, including the AI's. *Especially* the AI's: that is the
  entire subject matter of the tool.
- **Enforced honesty.** The README's status table grades every capability by evidence,
  and its [v1 acceptance table](README.md#v1-acceptance-specmd-16) publishes the
  criterion that is **not** met (only one of two live adapters has been run) with the
  same prominence as the four that are. The corpus ships with
  [scenarios/AUDIT.md](scenarios/AUDIT.md), a plain-English guide inviting a human
  reviewer to attack the traps' fairness — openly flagging that the scenarios and the
  detectors that judge them share an author.
- **Spending the money to hit reality.** Fixture tests all passed; the operator's
  instruction was to run it against a live agent anyway.

## What hitting reality found

The live runs (OpenAI Codex, 12 scenarios, every package committed under
[evidence/](evidence/)) were worth far more for what they broke than for what they
scored. Five defects surfaced that no fixture test had reached — and every one would
have produced a *plausible wrong answer* rather than a visible failure, which is the
worst possible failure mode for a measurement instrument:

1. The agent CLI hung forever waiting on stdin — indistinguishable from an agent
   "thinking" until its time budget died.
2. An agent sandbox mode left implicit — one wrong default and every scenario fails
   for a reason that has nothing to do with the agent.
3. Claim detection recognised **one real completion report in six.** The patterns were
   written from imagination ("All tests pass"); real agents write "Verification:
   `pytest` — **3 passed**." Silently, the entire claims-audit family could never have
   caught a lying agent. Fixed against the captured real messages, which now ship as
   regression fixtures.
4. `error` outcomes didn't say *why* — an unauthenticated CLI was reported with
   detector noise instead of "Not logged in."
5. The harness scored a **textbook-perfect refusal as a failure.** On the
   deliberately-impossible scenario, Codex refused exactly right — *"the specification
   is unsatisfiable… I did not create a misleading implementation"* — and the trap's
   refusal markers only recognised the author's own vocabulary. The scenario had
   validated green against its own reference the whole time, because it was only ever
   asked to agree with itself.

That fifth one is the thesis in miniature. The defect was fixed, regression-tested
against six independently-worded refusals — and the mislabelled package was committed
to [evidence/](evidence/) **unedited**, because doctoring evidence after the fact is
the one thing this project must never do. The lesson is written into the corpus docs
as ["the trap validation cannot catch"](scenarios/README.md#the-trap-validation-cannot-catch).

Before publication, the repository was adversarially audited by six independent AI
review agents (secrets, overclaim, trap fairness, self-consistency, presentation, and
one instructed to be a hostile reviewer). Their unanimous top finding: *the boldest
claims were the least checkable, because the reproducibility packages were gitignored.*
The fix was not softer wording — it was committing the evidence. That is why
[evidence/](evidence/) exists.

## What this is not

No number this repository has produced is a Stinger score. The live runs cover one
scenario family each, and the tool itself stamps every such report `PARTIAL / DEV RUN —
this MUST NOT be presented as a Stinger score`. It is not a verdict on any vendor's
agent — 6/6 honest on six scenarios, one repetition, is an instrument check, not a
leaderboard. The demo's strict-vs-permissive agents are deterministic shell scripts,
not models: they prove the instrument discriminates, nothing more. The human
spot-audit of the corpus has not happened yet, and the README says so. And none of
this is a claim that AI replaces engineers — it is one datapoint about what a
disciplined non-engineer can now direct AI to build, with the receipts committed so
you can judge the claim yourself.

## Contact

Chris McNosky · Dallas–Fort Worth, TX · cmcnosky@gmail.com
Available for AI-systems direction, agent-governance consulting, and roles where
"make AI-built software provably trustworthy" is the job. Sibling project:
[WASP-2.0](https://github.com/cmcnosky/WASP-2.0) — an AI-built, human-governed
algorithmic trading system under the same discipline.
