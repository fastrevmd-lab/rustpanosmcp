#!/usr/bin/env bash
# Prove that the consistency test actually catches path mismatches by sabotaging
# the installer and showing the test fails, then restoring and showing it passes.
# This was P2: the test existed but was never invoked by verify-packaging.sh or CI.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PACKAGE_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd -P)"
INSTALL_SH="$PACKAGE_ROOT/packaging/lxc/install.sh"
CONSISTENCY_TEST="$PACKAGE_ROOT/packaging/lxc/tests/test_install_unit_consistency.sh"

# Verify the consistency test exists and is executable
if [[ ! -x "$CONSISTENCY_TEST" ]]; then
    echo "FAIL: consistency test does not exist or is not executable" >&2
    exit 1
fi

# Run it on the current (correct) state - should pass
if ! "$CONSISTENCY_TEST" >/dev/null 2>&1; then
    echo "FAIL: consistency test failed on correct install.sh" >&2
    "$CONSISTENCY_TEST" >&2
    exit 1
fi

# Create a backup
BACKUP="$(mktemp)"
trap '[[ -f "$BACKUP" ]] && mv "$BACKUP" "$INSTALL_SH"; rm -f "$BACKUP"' EXIT
cp "$INSTALL_SH" "$BACKUP"

# Sabotage: change $STATE_DIR/tokens.json to $CONFIG_DIR/tokens.json in a chmod line
# This creates a mismatch - the installer touches /etc/tokens.json but the unit references /var/lib
# shellcheck disable=SC2016  # The sed pattern contains literal $STATE_DIR to match source text
sed -i 's|chmod 0600 "\$STATE_DIR/tokens\.json"|chmod 0600 "$CONFIG_DIR/tokens.json"|' "$INSTALL_SH"

# Run the consistency test again - should now FAIL
if "$CONSISTENCY_TEST" >/dev/null 2>&1; then
    echo "FAIL: consistency test passed on sabotaged install.sh (should have failed)" >&2
    mv "$BACKUP" "$INSTALL_SH"
    exit 1
fi

# Restore
mv "$BACKUP" "$INSTALL_SH"

# Run again - should pass
if ! "$CONSISTENCY_TEST" >/dev/null 2>&1; then
    echo "FAIL: consistency test failed after restoring install.sh" >&2
    exit 1
fi

echo "PASS: consistency test catches path mismatches and is now invoked by verify-packaging.sh"
