#!/usr/bin/env bash
# Test that the stale secrets scan uses different live-file lists for /etc and /var/lib,
# so a legacy /etc/rust-panosmcp/tokens.json is flagged while /var/lib/rust-panosmcp/tokens.json is not.
# This was P2: the same live_files array was used for both, so tokens.json in /etc was never flagged.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PACKAGE_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd -P)"
MAIN_RS="$PACKAGE_ROOT/rust-panosmcp/src/main.rs"

# Check that the code defines separate live file arrays
if ! grep -q "config_live_files" "$MAIN_RS"; then
    echo "FAIL: main.rs does not define config_live_files" >&2
    exit 1
fi

if ! grep -q "state_live_files" "$MAIN_RS"; then
    echo "FAIL: main.rs does not define state_live_files" >&2
    exit 1
fi

# Check that config_live_files does NOT include tokens.json (legacy path should be flagged)
# It's a single-line array after rustfmt
CONFIG_LINE=$(grep 'let config_live_files = ' "$MAIN_RS")
if echo "$CONFIG_LINE" | grep -q '"tokens.json"'; then
    echo "FAIL: config_live_files includes tokens.json - legacy /etc path won't be flagged" >&2
    echo "Line: $CONFIG_LINE" >&2
    exit 1
fi

# Check that state_live_files DOES include tokens.json (live path should not be flagged)
STATE_ARRAY=$(sed -n '/let state_live_files = \[/,/\];/p' "$MAIN_RS")
if ! echo "$STATE_ARRAY" | grep -q '"tokens.json"'; then
    echo "FAIL: state_live_files does not include tokens.json" >&2
    exit 1
fi

# Check that the two arrays are passed to different find_stale_secrets calls
if ! grep -q 'find_stale_secrets(config_dir, &config_live_files)' "$MAIN_RS"; then
    echo "FAIL: config scan does not use config_live_files" >&2
    exit 1
fi

if ! grep -q 'find_stale_secrets(state_dir, &state_live_files)' "$MAIN_RS"; then
    echo "FAIL: state scan does not use state_live_files" >&2
    exit 1
fi

echo "PASS: stale scan uses separate live-file lists, legacy /etc/tokens.json will be flagged"
