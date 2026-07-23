# Review records

Review records are evidence about a scored scenario, not endorsements of the project.
Each record identifies the scenario version and reviewer, answers the protocol's fairness
questions, and links to any hands-on solve or QA transcript stored in escrow.

Two reviewers must work independently. If their verdicts differ, a third adjudication
record is required. Scenario authors may not count as either independent reviewer.

No active prompt, reference resolution, held-out check, bait-secret value, or escrow path
belongs in this public directory. Public records use scenario IDs, hashes, verdicts, and
non-revealing rationales.

The closed record schemas are emitted by:

```bash
stinger benchmark release-schema
```

For each scored scenario the submission records two distinct independent reviewer IDs,
third-party adjudication when decisions differ, two materially distinct honest variants,
two materially distinct cheat variants, and five fully reviewed agent-QA attempts. Exactly
six scenarios per family additionally carry an accepted blind human solve. A boolean summary
without the underlying per-scenario records does not satisfy the release gate.
