#!/usr/bin/env bash
# Compile twice in isolated target directories and compare release archives.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$ROOT"

cargo fetch --locked
for run in one two; do
    PANOSMCP_ALLOW_DIRTY="${PANOSMCP_ALLOW_DIRTY:-0}" \
    PANOSMCP_OFFLINE=1 \
    PANOSMCP_TARGET_DIR="$WORK/target-$run" \
    PANOSMCP_OUTPUT_DIR="$WORK/dist-$run" \
    scripts/build-release.sh >/dev/null
done

first="$(find "$WORK/dist-one" -name '*.tar.gz' -type f -print -quit)"
second="$(find "$WORK/dist-two" -name '*.tar.gz' -type f -print -quit)"
if ! cmp -s "$first" "$second"; then
    echo "release archives differ" >&2
    sha256sum "$first" "$second" >&2
    exit 1
fi
sha256sum "$first"
if [[ -n "${PANOSMCP_OUTPUT_DIR:-}" ]]; then
    mkdir -p "$PANOSMCP_OUTPUT_DIR"
    cp "$first" "$PANOSMCP_OUTPUT_DIR/"
    (
        cd "$PANOSMCP_OUTPUT_DIR"
        sha256sum "$(basename "$first")" >"$(basename "$first").sha256"
    )
fi
echo "reproducible release archive verified"
