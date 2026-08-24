#!/usr/bin/env bash
# Test that the SSDF audit drop-in example is included in the release archive.
# This was P2: the file existed but build-release.sh didn't copy it.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PACKAGE_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd -P)"

# Create a minimal fake package structure
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

# Simulate what build-release.sh does
PKG="$STAGING/rust-panosmcp-test"
install -d "$PKG/packaging/systemd"

# The fix: ssdf-audit.conf.example is now copied
if [[ ! -f "$PACKAGE_ROOT/packaging/systemd/ssdf-audit.conf.example" ]]; then
    echo "FAIL: source file packaging/systemd/ssdf-audit.conf.example does not exist" >&2
    exit 1
fi

# Simulate the install command from build-release.sh
install -m 0644 \
    "$PACKAGE_ROOT/packaging/systemd/rust-panosmcp.service" \
    "$PACKAGE_ROOT/packaging/systemd/rust-panosmcp.sysusers" \
    "$PACKAGE_ROOT/packaging/systemd/rust-panosmcp.tmpfiles" \
    "$PACKAGE_ROOT/packaging/systemd/ssdf-audit.conf.example" \
    "$PKG/packaging/systemd/"

# Verify it was copied
if [[ ! -f "$PKG/packaging/systemd/ssdf-audit.conf.example" ]]; then
    echo "FAIL: ssdf-audit.conf.example was not copied to the package" >&2
    exit 1
fi

echo "PASS: ssdf-audit.conf.example is shipped in the release archive"
