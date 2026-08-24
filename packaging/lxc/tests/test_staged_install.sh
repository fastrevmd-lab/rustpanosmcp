#!/usr/bin/env bash
# Test that staged installs (SKIP_USER_SETUP=1, INSTALL_ROOT=/path) work without
# systemd-tmpfiles creating directories. This catches the regression where
# $STATE_DIR/tokens.json is written before $STATE_DIR exists.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PACKAGE_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd -P)"

# Create a staging area that looks like a built package
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

FAKE_PACKAGE="$STAGING/rust-panosmcp-test"
install -d "$FAKE_PACKAGE/bin" "$FAKE_PACKAGE/packaging/systemd" "$FAKE_PACKAGE/packaging/lxc" \
    "$FAKE_PACKAGE/config"

# Copy the installer and required files
cp "$PACKAGE_ROOT/packaging/lxc/install.sh" "$FAKE_PACKAGE/packaging/lxc/install.sh"
cp "$PACKAGE_ROOT/packaging/systemd/rust-panosmcp.service" "$FAKE_PACKAGE/packaging/systemd/"
cp "$PACKAGE_ROOT/packaging/systemd/rust-panosmcp.sysusers" "$FAKE_PACKAGE/packaging/systemd/"
cp "$PACKAGE_ROOT/packaging/systemd/rust-panosmcp.tmpfiles" "$FAKE_PACKAGE/packaging/systemd/"
cp "$PACKAGE_ROOT/config/devices.example.json" "$FAKE_PACKAGE/config/"

# Create a fake binary
echo '#!/bin/sh' > "$FAKE_PACKAGE/bin/rust-panosmcp"
echo 'echo "fake binary"' >> "$FAKE_PACKAGE/bin/rust-panosmcp"
chmod +x "$FAKE_PACKAGE/bin/rust-panosmcp"
chmod +x "$FAKE_PACKAGE/packaging/lxc/install.sh"

# Run the installer in staged mode
INSTALL_ROOT="$STAGING/staged"
export PANOSMCP_INSTALL_ROOT="$INSTALL_ROOT"
export PANOSMCP_INSTALL_SKIP_USER=1
export PANOSMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1
export PANOSMCP_INSTALL_SKIP_RUNTIME_DEPS=1

cd "$FAKE_PACKAGE"
./packaging/lxc/install.sh

# Verify that $STATE_DIR was created and tokens.json exists
STATE_DIR="$INSTALL_ROOT/var/lib/rust-panosmcp"
if [[ ! -d "$STATE_DIR" ]]; then
    echo "FAIL: $STATE_DIR was not created by staged install" >&2
    exit 1
fi

if [[ ! -f "$STATE_DIR/tokens.json" ]]; then
    echo "FAIL: $STATE_DIR/tokens.json was not created by staged install" >&2
    exit 1
fi

# Verify tokens.json has correct permissions
PERMS=$(stat -c '%a' "$STATE_DIR/tokens.json")
if [[ "$PERMS" != "600" ]]; then
    echo "FAIL: tokens.json has mode $PERMS, expected 600" >&2
    exit 1
fi

echo "PASS: staged install creates $STATE_DIR and tokens.json with correct permissions"
