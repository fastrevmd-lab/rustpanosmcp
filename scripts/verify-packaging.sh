#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

systemd-analyze verify packaging/systemd/rust-panosmcp.service
rg -q '^USER 65532:65532$' Dockerfile
rg -q '^ENTRYPOINT \["/usr/local/bin/rust-panosmcp"\]$' Dockerfile
rg -q '^FROM rust:.*@sha256:[0-9a-f]{64} AS builder$' Dockerfile
rg -q '^FROM gcr.io/distroless/cc-debian12:nonroot@sha256:[0-9a-f]{64}$' Dockerfile
if rg -n '(^|[[:space:]])(curl|wget|apt-get|apk|dnf)([[:space:]]|$)' Dockerfile; then
    echo "runtime/container build contains an unapproved package-fetch command" >&2
    exit 1
fi
echo "packaging policy checks passed"
