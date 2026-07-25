#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

diagnostics="$(mktemp)"
trap 'rm -f "$diagnostics"' EXIT
if ! systemd-analyze verify packaging/systemd/rust-panosmcp.service 2>"$diagnostics"; then
    if grep -Ev '^rust-panosmcp\.service: Command /usr/local/bin/rust-panosmcp is not executable: No such file or directory$' \
        "$diagnostics" | grep -q .; then
        cat "$diagnostics" >&2
        exit 1
    fi
fi
cat "$diagnostics" >&2

grep -Eq '^USER 65532:65532$' Dockerfile
grep -Eq '^ENTRYPOINT \["/usr/local/bin/rust-panosmcp"\]$' Dockerfile
grep -Eq '^FROM rust:.*@sha256:[0-9a-f]{64} AS builder$' Dockerfile
# Pins the approved runtime base. This must move whenever the Dockerfile's base
# moves — it is the check that stops the base drifting silently, so it is
# deliberately exact rather than a wildcard over distroless variants.
grep -Eq '^FROM gcr.io/distroless/cc-debian13:nonroot@sha256:[0-9a-f]{64}$' Dockerfile
if grep -En '(^|[[:space:]])(curl|wget|apt-get|apk|dnf)([[:space:]]|$)' Dockerfile; then
    echo "runtime/container build contains an unapproved package-fetch command" >&2
    exit 1
fi
echo "packaging policy checks passed"
