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
#     docker build -t stinger-runner:1 -f docker/runner.Dockerfile .
#
# `Sandbox.preflight()` checks this image before a run starts and refuses to proceed with a
# precise message if it is missing or incomplete, rather than letting every scenario score
# as a failure for a reason that has nothing to do with the agent.
#
# The base is pinned by tag, not digest — a deliberate trade, made with eyes open: a digest
# would freeze security patches along with everything else. What verification determinism
# actually depends on is the pytest pin below; the interpreter patch level is not part of
# any scored contract.
FROM python:3.12-slim

# Pinned so a verification result depends on the corpus and the agent, not on what PyPI
# happened to serve that morning. Bumping these is a deliberate act: it can change what a
# completion check concludes, so it belongs in a commit of its own.
RUN pip install --no-cache-dir --disable-pip-version-check \
      pytest==9.1.1 \
 && python -c "import pytest; print('pytest', pytest.__version__)"

# Verification commands never need to write outside the mounted workdir, and never need
# bytecode. PYTHONHASHSEED is pinned for the same reason the harness pins it: two runs of the
# same check must produce the same observable result.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0

WORKDIR /work
