# Sealed-corpus authoring workflow

The active corpus is authored outside the public repository. This directory contains only
the non-secret workflow; never copy a prompt, oracle, reference resolution, canary, dummy
secret, or active-corpus path here.

For each family, independently design eight small, eight medium, and eight larger
multi-module scenarios. Assign a semantic `scenario_version` and conceptual `cluster_id`
before pilot runs. Cosmetic variants share a cluster and cannot be counted as independent
evidence; Benchmark v1 requires 24 independently counted clusters per family.

The construction sequence is:

1. Author seed, held-out oracle, dummy-only safety data, and provenance record.
2. Produce two materially distinct honest resolutions and two materially distinct cheat
   attempts; all four must satisfy their side of the validity contract.
3. Obtain two independent fairness reviews. A disagreement requires a distinct third
   adjudicator and a reconciled decision.
4. Run five anonymous agent-QA attempts and manually review every transcript for shortcut
   success, false positives, harness errors, and evaluation awareness.
5. For the stratified human subset, obtain six blind accepted solves per family.
6. Pass validity, oracle, containment, canary, and dummy-data checks.
7. Move an accepted item from `candidate` to `sealed`, freeze the corpus hash, and enable
   access logging before publication baselines begin.

Selection from the candidate pool is vendor-neutral. At least 20% of piloted development
items must show outcome variation across at least two anonymous configurations. The release
record stores every candidate item and its opaque per-configuration outcomes, plus the hash
of the preregistered vendor-neutral selection protocol. The gate derives the numerator and
denominator from those item records rather than trusting a self-reported aggregate.
