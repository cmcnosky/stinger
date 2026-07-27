#!/bin/sh
# Ordinary-development helper: seed writable CODEX_HOME from a read-only credential mount,
# then exec the agent.
#
# Protocol 2 rejects `credential_mount`; its external broker keeps the raw credential outside
# this container and projects only an opaque lease plus the signed `openai_base_url` CLI
# override, never `OPENAI_BASE_URL`. On that sealed path `/credentials` is absent and this
# script goes directly to `exec "$@"`. Before launch, Protocol 2 has already required the
# declared/default agent config home to be absent or empty and scanned final argv, workdir,
# image metadata, and exported final rootfs for raw and encoded credential forms plus signed
# prohibited paths. This helper is not evidence that a copied credential is isolated from a
# networked agent.
#
# The Codex CLI writes into CODEX_HOME on startup — PATH aliases, an app-server client — so
# pointing CODEX_HOME straight at the mount fails with "Read-only file system (os error 30)"
# before the agent runs at all. Making the mount writable instead would be the wrong trade:
# the agent under test is the untrusted party in this harness, and a writable host mount is a
# channel out of the container and a way to tamper with the operator's credentials.
#
# So the mount stays read-only and its contents are copied into the image's own writable
# CODEX_HOME, which lives only for the life of the container. One consequence worth knowing:
# a token the CLI refreshes during a run is refreshed in the copy and discarded with it, so
# the operator's credential file on the host never changes — refreshing it is a manual step.
set -eu

if [ -d /credentials ] && [ "${CODEX_HOME}" != "/credentials" ]; then
    # -R, not -a: the container runs as the invoking user's uid, which owns neither the
    # read-only source nor the image-built CODEX_HOME, so preserving timestamps and ownership
    # fails with "Operation not permitted". None of that metadata matters to the CLI.
    # No chmod afterwards: cp creates the copies owned by the running uid with default
    # permissions, which is already what the CLI needs. Chmod'ing CODEX_HOME itself fails —
    # the directory was built as root, and 1777 lets a non-owner write inside it but not
    # change it.
    cp -R /credentials/. "${CODEX_HOME}/"
elif [ "${CODEX_HOME}" = "/credentials" ]; then
    # Config pointed CODEX_HOME straight at the read-only mount, which is the mistake this
    # script exists to prevent. Say so instead of failing later inside the CLI, where it
    # surfaces as an unexplained exit 1 and scores the scenario as a harness error.
    echo "codex-agent-entrypoint: CODEX_HOME must not be /credentials — leave it at the" >&2
    echo "  image default so the read-only credential mount can be copied into it." >&2
    exit 64
fi

exec "$@"
