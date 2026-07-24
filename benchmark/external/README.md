# Outside validation workflow

Benchmark v1 needs evidence from people who did not build Stinger.

Three outside beta operators each run the public development suite and record whether setup
errors, protocol ambiguities, and interpretation differences occurred—even when the answer
is “none.” Their records contain identities and non-secret findings, never active sealed
material.

After the protocol and corpus freeze, one unaffiliated evaluator receives the
access-controlled escrow bundle and reproduces one complete five-family baseline on a
separate machine. The evaluator verifies the independently obtained protocol signer trust
policy, exact inventories, score and interval recomputation, corpus hash, configuration
pins, and every discrepancy. An unreconciled discrepancy blocks release.

The evaluator records those checks in an `IndependentReproductionStatement` that binds the
target and reproduced reports, canonical agent-configuration fingerprints, public and
escrow manifest hashes, distinct machine fingerprints, comparison artifact, and exact
discrepancy ledger. The evaluator signs the statement under the dedicated reproduction
signature namespace. Release verification receives the evaluator's `allowed_signers`
policy out of band; project-supplied trust is not accepted as proof of independence.

These are human coordination gates. The repository supplies schemas and verification tools;
it cannot truthfully manufacture outside operators, independence, separate-machine
execution, or Chris's final approval.
