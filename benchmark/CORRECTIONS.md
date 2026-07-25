# Benchmark correction and corpus-retirement policy

This document is the reader-facing explanation. Protocol 2 publication credit comes from
the canonical generated `CorrectionPolicyArtifact`, whose fixed triggers and actions cannot
be omitted or weakened by a caller. The signed release-evidence statement binds those exact
typed bytes.

Benchmark evidence is append-only at the claim boundary. A released corpus, protocol, or
result is never silently edited in place.

When a task defect, detector defect, leakage event, or protocol ambiguity is confirmed:

1. Record the affected scenario/version, discovery source, evidence, and impact without
   disclosing active sealed material.
2. Quarantine affected active scenarios and stop new comparative publication while impact
   is unresolved.
3. Assign a new scenario, corpus, protocol, or tool version according to what changed.
   `RUBRIC_VERSION` changes only when the frozen scoring formula changes.
4. Recompute every affected baseline where the original evidence permits it. Mark results
   that cannot be recomputed as superseded, never deleted.
5. Publish the correction, affected-result list, before/after methodology, uncertainty
   impact, and whether rankings or conclusions changed.
6. Notify affected vendors and offer a rerun before corrected comparative results are
   presented.

When an active corpus retires, release its complete prompts, seed repositories, references,
held-out checks, construction records, and correction history after checking that all
credentials and targets are dummy/local. The successor corpus receives a new version,
canaries, access log, freeze record, and baseline matrix.

One documented correction/version cycle plus at least three accepted cross-machine runs
from distinct environment fingerprints is required before the project may consider the
stronger phrase “established benchmark.” Those records support environment diversity; they
do not by themselves prove organizational affiliation or physical-machine identity.
