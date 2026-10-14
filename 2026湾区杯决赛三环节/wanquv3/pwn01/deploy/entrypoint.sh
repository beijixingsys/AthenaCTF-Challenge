#!/bin/sh
# entrypoint.sh -- write the platform-injected flag into /flag, then serve the challenge.
#
# Why this file exists (2026-09-28): the platform generates a per-instance flag
#   flag{<64 hex>}
# hashes it into challenge_instance.game_flag_hash and passes the PLAINTEXT to the
# container through the FLAG environment variable (see platform source
# internal/arena/docker.go: `cmd.Env = append(filtered, "FLAG="+flag)` and `--env FLAG`).
# The image used to hardcode a placeholder at build time and ignore $FLAG, so the
# flag inside the container never matched the platform's hash => unsolvable.
#
# IMPORTANT: the platform starts containers with `--cap-drop=ALL` and
# `--security-opt=no-new-privileges:true`. Dropping ALL capabilities removes
# CAP_DAC_OVERRIDE, so root can NOT rewrite a root-owned mode-0444 /flag in place.
# Therefore we delete it first (unlink needs write permission on "/", which the
# owner has) and create a fresh file. Deliberately NO `set -e`: a failure here
# must never kill the service.
set -u

FLAG_VALUE="${FLAG:-}"
PLACEHOLDER='flag{placeholder_round3_pwn01_not_obtained}'

if [ -n "$FLAG_VALUE" ]; then
    # strip CR/LF without relying on external tr
    FLAG_VALUE=$(printf '%s' "$FLAG_VALUE" | sed -e 's/\r//g' -e 's/\n//g' 2>/dev/null || printf '%s' "$FLAG_VALUE")
    rm -f /flag 2>/dev/null || true
    if printf '%s\n' "$FLAG_VALUE" > /flag 2>/dev/null; then
        echo "[entrypoint] /flag written from injected FLAG (${#FLAG_VALUE} bytes)"
    else
        echo "[entrypoint] WARN: could not write /flag from FLAG; falling back"
    fi
fi

if [ ! -s /flag ]; then
    rm -f /flag 2>/dev/null || true
    printf '%s\n' "$PLACEHOLDER" > /flag 2>/dev/null || true
    echo "[entrypoint] using build-time placeholder flag (local run, no FLAG injected)"
fi

chmod 0444 /flag 2>/dev/null || true

exec socat TCP-LISTEN:9999,reuseaddr,fork EXEC:/app/pwn
