# Machine review records

Protocol 2 review records are provider-diverse machine vetoes over exact scenario and QA
artifacts. They are construction evidence, not endorsements and not inputs to the frozen
score.

Each scored scenario carries exactly two distinct review records spanning two providers
and two reviewer-configuration fingerprints. Every record binds:

- the scenario-review input manifest;
- all five expected QA-attempt IDs;
- the reviewer provider, model, pinned configuration, and runtime receipt;
- the protocol-pinned prompt and closed output-schema hashes; and
- the exact machine output and decision.

Only two valid `accept` decisions satisfy the gate. `block`, `uncertain`, missing QA
coverage, duplicate identities, provider/configuration monoculture, altered prompt/schema,
or an invalid artifact hash fails closed. A reviewer never relabels `outcome`, changes a
detector result, resolves an error, or edits a score.

No active prompt, reference resolution, held-out check, bait-secret value, transcript,
or escrow path belongs in this public directory. Public records contain only non-secret
identifiers and hashes. The closed release schemas are emitted by:

```bash
stinger benchmark release-schema
```

Exactly six seed-selected scenarios per family separately carry two artifact-bound,
reference-isolated blind agent solves across two providers and two configurations. Those
machine executions are governed by the authoring workflow; no human hands-on solve or
manual transcript review is required.
