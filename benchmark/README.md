# Benchmark Protocol 2 program

This directory holds the public control plane for the Stinger Benchmark candidate.
No scored corpus is currently active or claimed.

- [`../BENCHMARK.md`](../BENCHMARK.md) is the normative candidate protocol.
- `protocol.yaml` is the machine-readable protocol consumed by benchmark validation.
- `candidate-submission.yaml` is the truthful currently blocked release record.
- `STATUS.md` records earned and unearned release gates.
- `EVIDENCE.md` is the signed public/escrow bundle operator guide.
- `CORRECTIONS.md` explains the append-only correction and corpus-retirement policy; release
  credit comes from the generated closed `CorrectionPolicyArtifact`.
- `TECHNICAL_REPORT_TEMPLATE.md` is an optional reader-facing companion outline. The gate
  report is generated as a deterministic closed evidence index and accepts no free prose.
- `reviews/` documents provider-diverse machine-veto records and their frozen contract.
- `baselines/` holds non-secret configuration manifests and accepted public evidence.
- `authoring/` documents the sealed-corpus construction workflow.
- `external/` documents clean-environment conformance and cross-machine reproduction.
- `reproductions/` documents non-secret cross-machine reproduction records.

Local active-corpus and escrow material belongs in ignored directories:
`benchmark/sealed/` and `benchmark/escrow/`. Keeping a file out of Git is not encryption;
those directories still require normal filesystem access control.

The current local authoring checkout may also expose an ignored
`benchmark/sealed-candidate` symlink to the externally stored 120-scenario candidate
checkpoint. The ignored name and symlink are conveniences, not sealing or access control.
The checkpoint is construction evidence only; it must not be committed, treated as the
scored corpus, or entered into `candidate-submission.yaml` until the Protocol 2 validation
receipt, provider-diverse machine review, QA, blind-agent-solve, pilot, freeze, and release
gates are actually satisfied.

The existing [`../scenarios/`](../scenarios/) corpus is the public development and
conformance split. It is intentionally unsuitable for a headline benchmark score because
its reference resolutions and held-out checks are public.

Useful mechanical checks:

```bash
stinger benchmark protocol-check benchmark/protocol.yaml
stinger benchmark release-schema > /tmp/stinger-benchmark-release.schema.json
stinger benchmark release-check benchmark/candidate-submission.yaml
```

The final command currently fails by design. Do not change booleans or paste hashes into
the candidate submission to make it green; replace placeholders only with records derived
from verified machine evidence. Chris's final signed authorization is required only after
every machine gate is earned and is never a scoring or transcript-review input.
