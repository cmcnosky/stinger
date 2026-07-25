# The container Stinger runs verification commands in (SPEC.md §2).
#
# Verification means the held-out completion check and the detectors' clean test re-run.
# Those run with the network disabled, which means everything they need must already be in
# the image — `python:3.12-slim` alone is NOT enough, because it ships no pytest, and a
# completion check that fails on a missing import is indistinguishable downstream from one
# that fails because the agent did not do the work. That would manufacture failures rather
# than measure them.
#
# Build it before the first Docker run:
#
#     build_dir="$(mktemp -d)"
#     docker buildx build --no-cache --provenance=false \
#       --build-arg SOURCE_DATE_EPOCH=0 --platform linux/arm64 \
#       -t stinger-runner:1 \
#       --output type=docker,rewrite-timestamp=true,dest="$build_dir/runner.tar" \
#       -f docker/runner.Dockerfile docker/
#     docker load --input "$build_dir/runner.tar"
#
# `Sandbox.preflight()` checks this image before a run starts and refuses to proceed with a
# precise message if it is missing or incomplete, rather than letting every scenario score
# as a failure for a reason that has nothing to do with the agent.
#
# Benchmark evidence must identify exact verifier bytes. Security updates are therefore
# explicit policy updates: change this digest, rebuild, record the new immutable image ID,
# and re-freeze the signed benchmark protocol.
FROM python@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

# Verification commands and the package installation never need bytecode.
# PYTHONHASHSEED is pinned for the same reason the harness pins it: two runs of the same
# check must produce the same observable result. Setting this before pip also prevents
# timestamp-bearing `.pyc` files from making otherwise identical image builds diverge.
# pip's explicit bytecode compilation does not honor PYTHONDONTWRITEBYTECODE, so the
# installation command also uses `--no-compile`.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0

# Every direct and transitive wheel is version- and hash-pinned. The build context is the
# `docker/` directory, and this lock plus this Dockerfile are the complete source inventory
# committed by the signed verification-image policy.
COPY runner-requirements.lock /tmp/runner-requirements.lock
RUN python -m pip install --no-cache-dir --disable-pip-version-check \
      --no-compile --require-hashes -r /tmp/runner-requirements.lock \
 && python -c "import pytest; print('pytest', pytest.__version__)"

WORKDIR /work
