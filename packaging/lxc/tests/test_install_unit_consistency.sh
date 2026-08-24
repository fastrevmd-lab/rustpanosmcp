#!/usr/bin/env bash
# Test that install.sh creates/modifies only files referenced by the shipped unit.
#
# This catches the class of bug where the installer hardens the wrong file
# (e.g., /etc/rust-panosmcp/tokens.json) while the unit reads another
# (/var/lib/rust-panosmcp/tokens.json). Such bugs are invisible to a runtime
# smoke test because the server starts fine — only this cross-reference catches them.

set -euo pipefail

# Resolve script directory to find the package root.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PACKAGE_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd -P)"

UNIT_FILE="$PACKAGE_ROOT/packaging/systemd/rust-panosmcp.service"
INSTALL_SCRIPT="$PACKAGE_ROOT/packaging/lxc/install.sh"

if [[ ! -f "$UNIT_FILE" ]]; then
    echo "FAIL: unit file not found at $UNIT_FILE" >&2
    exit 1
fi

if [[ ! -f "$INSTALL_SCRIPT" ]]; then
    echo "FAIL: install script not found at $INSTALL_SCRIPT" >&2
    exit 1
fi

# Extract all paths from ExecStart lines in the unit file.
# Matches: --flag /path/to/file
UNIT_PATHS=$(grep -E '^\s*(ExecStart=|--[a-z-]+\s+/)' "$UNIT_FILE" \
    | grep -oE '(--[a-z-]+\s+)?(/[a-z/_-]+\.[a-z.]+)' \
    | grep -oE '/[a-z/_-]+\.[a-z.]+' \
    | sort -u)

# Extract paths that install.sh creates, chmods, or chowns.
# This captures lines like:
#   printf ... >"$STATE_DIR/tokens.json"  (actual redirect, not a message)
#   chmod 0600 "$STATE_DIR/tokens.json"
#   chown ... "$CONFIG_DIR/audit-hmac.key"
# Match only lines with actual file operations: chmod, chown, redirects (>"), or
# head/base64 pipes. Exclude plain printf messages (no redirect).
# shellcheck disable=SC2016  # We're matching literal $STATE_DIR in the script source
INSTALL_PATHS=$(grep -E '(chmod|chown|>"\$|head.*\||base64 >\$)' "$INSTALL_SCRIPT" \
    | grep -oE '(\$STATE_DIR|\$CONFIG_DIR)/[a-z._-]+' \
    | sed 's|\$STATE_DIR|/var/lib/rust-panosmcp|g; s|\$CONFIG_DIR|/etc/rust-panosmcp|g' \
    | sort -u)

# Check that every path the installer touches appears in the unit.
# Exceptions:
# - devices.json.example: it's an example, not used by the service
# - mutation-state.json: written by the service at runtime, not at install time
FAILS=0
for install_path in $INSTALL_PATHS; do
    # Skip expected exceptions
    if [[ "$install_path" == *"/devices.json.example" ]]; then
        continue
    fi

    if ! echo "$UNIT_PATHS" | grep -qF "$install_path"; then
        echo "FAIL: install.sh references $install_path, but it does not appear in the unit" >&2
        FAILS=$((FAILS + 1))
    fi
done

# Check that every file path in the unit is handled by the installer.
# The installer should either create it or document why it's excluded.
for unit_path in $UNIT_PATHS; do
    # mutation-state.json is created by the service at runtime, not by the installer
    if [[ "$unit_path" == *"/mutation-state.json" ]]; then
        continue
    fi
    # evidence files are created at runtime when SSDF is enabled
    if [[ "$unit_path" == *"/evidence-outbox.ndjson" ]] || \
       [[ "$unit_path" == *"/evidence-ledger.ndjson" ]]; then
        continue
    fi
    # audit.jsonl is created at runtime
    if [[ "$unit_path" == *"/audit.jsonl" ]]; then
        continue
    fi

    if ! echo "$INSTALL_PATHS" | grep -qF "$unit_path"; then
        echo "FAIL: unit references $unit_path, but install.sh does not create or harden it" >&2
        FAILS=$((FAILS + 1))
    fi
done

if [[ $FAILS -eq 0 ]]; then
    echo "PASS: all installer-touched paths appear in the unit, and vice versa"
    exit 0
else
    echo "FAIL: $FAILS path mismatches between install.sh and the unit" >&2
    exit 1
fi
