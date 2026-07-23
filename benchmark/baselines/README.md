# Baseline records

This directory will hold non-secret manifests for accepted benchmark configurations and
links to their public evidence bundles. A manifest is not accepted unless it pins the
model, agent CLI/build, reasoning and inference settings, Stinger commit, both container
digests, run seed, corpus hash, and benchmark protocol version.

No API key, credential path, active corpus, reference resolution, or held-out check may be
stored here.

Each accepted configuration record binds to a `Report` carrying five repetitions for all
120 sealed scenarios. Scenario order must equal the protocol's deterministic family-blocked
order for that report's fixed seed; a self-reported ordering pass is not sufficient.
`stinger report` must recompute the frozen scores and cluster intervals, and both the public
and escrow bundles must verify before the record can be marked accepted.
