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

Every accepted record must be created by
`stinger benchmark build-baseline-record`. Hand-entered artifact hashes, containment
booleans, ordering booleans, or bundle-verification booleans are not accepted construction
evidence. The builder derives the report hash, exact public/escrow manifest-file hashes,
machine-attestation hash, and favorable booleans only after the verified artifacts pass the
existing per-configuration release evaluator.

The machine-identity artifact is an out-of-band identity attestation, not proof of physical
hardware. The containment field records that the resolved run required Docker and that
stored runtime provenance matched the pinned images and invocation; it is not independent
per-process hardware telemetry. Escrow and active leakage material stay outside the public
release gate.
