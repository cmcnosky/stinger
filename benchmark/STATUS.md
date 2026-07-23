# Stinger Benchmark v1 status

Overall status: **benchmark candidate — HOLD on benchmark or vendor-comparison claims**

This table records evidence, not intention. `met` requires a committed or independently
verifiable artifact.

| Gate | Required | Current evidence | State |
|---|---:|---|---|
| Public development corpus | 30, six per family | `scenarios/` validates 30/30 in CI | met |
| Current-corpus live evidence | Contained, all five families, five repetitions, fully pinned | Historical T/S/C locks differ, G alone matches, and no X run exists | not met |
| Sealed scored corpus | 120, 24 per family | No active scored corpus is committed or claimed | not met |
| Independent fairness reviews | Two per scored scenario | Review workflow not yet completed | not met |
| Human blind solves | Six per family | No accepted solve records | not met |
| Agent QA | Five reviewed attempts per scored scenario | No accepted scored-corpus QA records | not met |
| Fully pinned baseline configs | Six across three providers | Existing evidence does not meet benchmark pins | not met |
| Contained five-family baselines | Five repetitions per configuration | No complete baseline exists | not met |
| Statistical publication mechanism | Clustered/paired intervals, nested repetitions, tamper check | Implemented and tested; no eligible sealed baseline exists | mechanism met; evidence not met |
| Deterministic blocked ordering | Fixed-seed family blocks, rechecked from results | Implemented and tested; no eligible sealed baseline exists | mechanism met; evidence not met |
| Public/escrow evidence mechanism | Signed protocol, leakage-checked public bundle, full escrow | Implemented and tested, including sealed-artifact CI refusal; no release bundle exists | mechanism met; evidence not met |
| Master release gate | Corpus, matrix, outside evidence, signed reproduction, and signed human approval | `candidate-submission.yaml` fails closed with stable issue codes | mechanism met; release not met |
| Signed frozen protocol | Trusted detached signature over frozen protocol | Signing/verification mechanism exists; no accepted protocol signature is claimed | not met |
| Signed release authorization | Chris signs exact final submission | Dedicated signature namespace and verification exist; no authorization is claimed | not met |
| Outside beta operators | Three | None recorded | not met |
| Independent reproduction | One complete sealed baseline and trusted signed artifact-binding statement | None recorded | not met |
| Human release approval | Explicit after all evidence gates | Not requested because prior gates are open | not met |

The existing live packages remain valuable instrument checks, but they are partial,
single-repetition, pre-benchmark evidence and are not promoted by this document.

Run `stinger benchmark release-check benchmark/candidate-submission.yaml` for the
machine-readable current blocker list. A non-zero exit is the expected truthful result.
