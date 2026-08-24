#!/usr/bin/env bash
# Test that the HMAC key creation is documented in the manual install path.
# This was P1: the service unconditionally uses --audit-hmac-key-file, but manual
# installs had no documented step to create it, causing restart loops.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PACKAGE_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd -P)"

README="$PACKAGE_ROOT/README.md"
OPERATIONS="$PACKAGE_ROOT/docs/OPERATIONS.md"

# Check that README documents HMAC key creation in the manual install section
if ! grep -q "audit-hmac.key" "$README"; then
    echo "FAIL: README.md does not mention audit-hmac.key" >&2
    exit 1
fi

if ! grep -q "head -c 32 /dev/urandom" "$README"; then
    echo "FAIL: README.md does not show HMAC key generation command" >&2
    exit 1
fi

# Check that OPERATIONS.md documents it in the systemd installation section
if ! grep -q "audit-hmac.key" "$OPERATIONS"; then
    echo "FAIL: OPERATIONS.md does not mention audit-hmac.key" >&2
    exit 1
fi

if ! grep -q "head -c 32 /dev/urandom" "$OPERATIONS"; then
    echo "FAIL: OPERATIONS.md does not show HMAC key generation command" >&2
    exit 1
fi

# Check that the service unit references the key file
if ! grep -q "audit-hmac-key-file" "$PACKAGE_ROOT/packaging/systemd/rust-panosmcp.service"; then
    echo "FAIL: service unit does not reference audit-hmac-key-file" >&2
    exit 1
fi

echo "PASS: HMAC key creation is documented in both README and OPERATIONS.md"
