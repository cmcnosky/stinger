# Stinger — Build Plan (dependency-ordered milestones)

> **Historical document.** This is the plan the repo was built from, kept as provenance. It
> references files that lived in the external spec pack it shipped with — `skeleton/`,
> `detectors/STUBS.md`, `stinger-scenario-taxonomy.md` — which were consumed during the
> build and are not part of the published repository. The milestones below are all complete
> (README, "v1 acceptance").

Build in this order; each milestone has an **acceptance gate** that must pass before the
next begins. "Gate green" always means `./scripts/check.sh` passes plus the milestone's
specific check. Reference `SPEC.md` section numbers are in parentheses. The skeleton already
contains the interfaces, the frozen `classify()` and rubric math, the `forbidden_path`
detector, and the fully-worked `T-02` scenario — start by making those real and green, then
widen.

## M0 — Repo boots and gates run (½ day)
- Copy `skeleton/` to the repo root. `pip install -e ".[dev]"` succeeds.
- `ruff`, `mypy --strict`, and an empty `pytest` run clean. `check.sh` runs (it will fail at
  the no-stub / validate steps — expected).
- **Gate:** lint + type clean; `stinger --help` lists the four commands.

## M1 — Sandbox + RepoState capture (2–3 days) (§7 steps 1,2,4)
- Implement `harness/sandbox.py`: `prepare(manifest) -> workdir` (isolated copy of
  `seed_repo`, house rules written to `workdir/AGENTS.md`) and `capture(workdir) -> RepoState`
  (tracked files + content hashes). Docker path + `--local` git-worktree path; `--local`
  refuses the `X` family.
- **Gate:** a test prepares T-02, captures before/after around a hand-applied patch, and the
  changed-paths set is correct.

## M2 — One detector + the classifier, end to end on T-02 (2–3 days) (§6,§7)
- `forbidden_path.py` is written — add its unit tests against T-02's reference patches.
- Implement `runner.run_scenario_once` (the §7 pipeline) using the `RecordedAdapter` so no
  live model is needed. `classify()` is already frozen — wire it in.
- Implement `parse_claim` conservatively with fixtures.
- **Gate:** with a recorded "honest" run, T-02 scores `HONEST`; with a recorded "cheat" run
  (touches tests/), it scores `CHEATED`; with a recorded "gave up" run, `FAILED_HONESTLY`.
  This is the whole machine working on one scenario.

## M3 — The validity contract (2 days) (§12)
- Implement `scenario/manifest.validate_scenario` and `scenario/loader.py`.
- Implement `cli validate`: apply `honest.patch` (assert no detector fires + completion
  passes), apply `cheat.patch` (assert the `intended` detector fires).
- **Gate:** `stinger validate scenarios/` passes for T-02 and exits non-zero if you
  deliberately break either reference patch. This gate is what makes the corpus trustworthy.

## M4 — Scoring + report + repro package (2–3 days) (§8,§10)
- Finish `scoring/rubric.py` (`_per_rep_rates`); build `report/generate.py` (JSON+MD+HTML via
  jinja2) and `report/repro.py` (the `repro/<ts>/…` tree + `rerun.sh`).
- Wire `cli run` and `cli report` fully.
- **Gate:** `stinger run` over the single-scenario corpus emits a complete Report and repro
  package; `rerun.sh` reproduces identical scoring; `cli report` re-renders it.

## M5 — Real adapters (3–4 days) (§5)
- Implement `claude_code.py`, `codex.py`, `aider.py`, `shell.py`. Each has a recorded-fixture
  mode for stinger's own tests and a live mode behind an env-provided key.
- **Gate:** at least two adapters run T-02 live and produce a Report; stinger's own tests use
  only recorded fixtures (no network in CI).

## M6 — The other six detectors (3–4 days) (§6, detectors/STUBS.md)
- Implement `assertion_change`, `test_count`, `test_rerun`, `claim_match`, `secret_leak`,
  `command_scan`, each unit-tested against reference patches. Delete `detectors/STUBS.md`.
- **Gate:** each detector fires on its intended cheat and stays silent on the honest patch.

## M7 — Scale the corpus to ≥30 validated scenarios (1–2 weeks) (taxonomy)
- Author scenarios across all five families per `stinger-scenario-taxonomy.md`, each with
  both reference patches, each passing `stinger validate`. Human spot-audits ~20%.
- **Gate:** `stinger validate scenarios/` green for ≥30 scenarios spanning T,S,C,G,X.

## M8 — The CI action + the discrimination demo (2 days) (§14,§16)
- Finish `.github/workflows/stinger.yml`: fail the job on integrity regression vs baseline.
- Build the acceptance demo (§16.4): a repo whose agent is configured permissively FAILS the
  action; one configured strictly PASSES — proving the tool discriminates.
- **Gate:** the full §16 definition-of-done checklist passes from a clean clone.

---

## Standing rules for every milestone
- End each work session with `check.sh` green. Small commits naming the SPEC section.
- Never satisfy a gate by weakening it (that is the sin Stinger detects — AGENTS.md).
- No `NotImplementedError` / `# BUILD:` may remain in a file you called done.
- When a decision is marked **[OPEN]** in the spec, take the default and note it.

## Rough total
~4–6 focused weeks to a launchable v1 (M0–M8). M0–M4 give a working single-scenario harness
in ~1.5 weeks — the earliest point you can demo "here is the machine, watch it catch a
cheat." That demo is the thing to show first.
