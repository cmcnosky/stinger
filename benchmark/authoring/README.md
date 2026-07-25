# Sealed-corpus authoring workflow

The active corpus is authored outside the public repository. This directory contains only
the non-secret workflow; never copy a prompt, oracle, reference resolution, canary, dummy
secret, or active-corpus path here.

For each family, design eight small, eight medium, and eight larger multi-module scenarios.
Assign a semantic `scenario_version` and conceptual `cluster_id` before pilot runs.
Cosmetic variants share a cluster and cannot count as separate evidence; Benchmark v1
requires 24 counted clusters per family.

The Protocol 2 construction sequence is:

1. Author the seed, held-out oracle, dummy-only safety data, provenance record, and
   authoring-configuration fingerprint.
2. Produce two materially distinct honest resolutions and two materially distinct cheat
   attempts. Bind each source tree, semantic patch, and execution receipt; all four must
   satisfy their side of the validity contract.
3. Run five contained agent-QA attempts across at least two pinned configurations and two
   providers. Bind every result, evidence manifest, runtime receipt, and outcome.
4. Run two provider-diverse machine veto reviews over the exact scenario-review manifest
   and all five QA attempts. The protocol-pinned prompt and output schema permit only
   `accept`, `block`, or `uncertain`; anything except two valid `accept` decisions excludes
   the item.
5. For the seed-17 stratified subset of six scenarios per family, run two
   reference-isolated blind agent solves across two configurations and two providers.
6. Pass validity, oracle, machine-validation, containment, provenance, canary, custody,
   and dummy-data checks.
7. Promote the complete accepted candidate snapshot into an otherwise byte-identical
   `sealed`-split, **unfrozen** corpus. Pilot that exact promoted snapshot anonymously under
   the protocol-frozen complete-corpus procedure. Only after the variation gate passes may
   the corpus receive its signed freeze record. Any scenario change requires a new
   candidate receipt and promotion; pilot outcomes never select or rewrite individual
   scenarios.

Machine reviews and blind solves never alter an agent result or score. They can only admit
or veto construction evidence. `block`, `uncertain`, missing artifacts, reference leakage,
harness error, provider/configuration monoculture, or contract-hash drift fails closed.

At least 20% of the promoted-but-unfrozen items must show outcome variation across at
least two anonymized configurations. The release record stores each item and its opaque
per-configuration outcomes plus the hash of the preregistered procedure. The gate derives
the rate from those records and requires the piloted scenario and cluster sets to equal
the subsequently frozen corpus exactly.
