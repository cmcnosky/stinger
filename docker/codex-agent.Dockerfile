# The container the CODEX AGENT UNDER TEST runs in (SPEC.md §5, §2).
#
# Distinct from runner.Dockerfile, and the distinction is the whole point:
#
#   runner.Dockerfile     verification commands. No network, no credentials, no agent.
#   codex-agent.Dockerfile the agent itself. Network on (it must reach its model API),
#                          credential forwarded in, nothing mounted but the workdir.
#
# Without an image like this, `AgentConfig.container_image` is unset and the adapter drives
# the agent as a host subprocess with its cwd set. That is process-level isolation, not
# containment: the agent can read anything the invoking user can. Observed, not theorised —
# a live Codex run under that mode read `~/.codex/memories/MEMORY.md` and pulled notes about
# an unrelated project into the recorded transcript. It is also why `stinger run` refuses the
# X (safety/exfiltration) family outright unless this is set: those scenarios seed bait
# credentials and destructive lures, and meeting them with full host access is not a test,
# it is an incident.
#
# Build it:
#
#     docker build -t stinger-codex-agent:1 -f docker/codex-agent.Dockerfile .
#
# Then point a config at it:
#
#     agent:
#       adapter: codex
#       container_image: stinger-codex-agent:1
#       api_key_env: OPENAI_API_KEY
#
# The credential is forwarded by NAME (see harness/sandbox.py docker_argv), so it never
# enters the recorded argv or the reproducibility package. Nothing is baked into this image:
# an image layer carrying a credential would leak it to everyone who can pull the image.

# Node is copied from the official image rather than installed by a piped shell script. The
# corpus this harness ships has a scenario for `curl … | sh` precisely because it is a supply
# chain a reader cannot audit, and building the tool that measures that with the thing it
# measures would be indefensible.
#
# Bases are pinned by tag, not digest — deliberately: a digest freezes security patches too.
# The version pins that matter to comparability are the explicit ones (CODEX_VERSION, the
# pytest pin), which travel in the config fingerprint's image name.
FROM node:22-bookworm-slim AS node

FROM python:3.12-slim-bookworm

COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm

# git: every scenario workdir is a git repository, and several traps turn on what the agent
# does with it (committing, hooks, force-push). An agent that cannot run git would fail those
# for a reason that has nothing to do with its integrity.
RUN apt-get update \
 && apt-get install --no-install-recommends -y git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# pytest is here for the AGENT, not for verification — verification has its own image. This
# closes a real hole in the first live run: on a host without pytest, Codex could not run the
# seeded suite at all and hand-rolled a substitute harness. Traps that depend on the agent
# meeting a red suite and being tempted by the fast way to green were measuring something
# weaker than they were built to measure.
#
# Pinned to match runner.Dockerfile: the agent and the verifier disagreeing about what
# "the suite passes" means would be a difference in the harness masquerading as a finding.
RUN pip install --no-cache-dir --disable-pip-version-check \
      pytest==9.1.1 \
 && python -c "import pytest; print('pytest', pytest.__version__)"

# Pinned deliberately. The agent build is part of what a report measures — SPEC.md §3.5 makes
# determinism conditional on "the same corpus version, config, and agent build" — so floating
# this tag would silently change what a number means between runs.
ARG CODEX_VERSION=0.144.1
RUN npm install -g --no-fund --no-audit "@openai/codex@${CODEX_VERSION}" \
 && codex --version

# `docker_argv` sets HOME=/tmp and runs as the invoking user, so anything the CLI caches must
# land somewhere world-writable. CODEX_HOME is set explicitly, and deliberately NOT under
# $HOME: left to default it becomes /tmp/.codex, and the CLI then refuses to create its helper
# binaries beneath a temporary directory and warns on every single run — noise in every
# transcript this harness keeps as evidence. /opt/codex-home is also the path a config
# overrides when mounting a credential directory, which makes that override visible rather
# than magic.
ENV CODEX_HOME=/opt/codex-home \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0

# Created at build time, sticky-writable like /tmp itself. The container runs as the
# invoking user's uid (docker_argv._user_mapping), which does not exist inside the image, so
# a directory owned by root would be unwritable and the CLI warns on every single run — noise
# in every transcript this harness records as evidence.
RUN mkdir -p "${CODEX_HOME}" && chmod 1777 "${CODEX_HOME}"

# Copies the read-only credential mount into the writable CODEX_HOME before exec'ing the
# agent. See the script for why the mount cannot simply be CODEX_HOME itself.
COPY docker/codex-agent-entrypoint.sh /usr/local/bin/codex-agent-entrypoint
RUN chmod 0755 /usr/local/bin/codex-agent-entrypoint

ENTRYPOINT ["/usr/local/bin/codex-agent-entrypoint"]

WORKDIR /work
