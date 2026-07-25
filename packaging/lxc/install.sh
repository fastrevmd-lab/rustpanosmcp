#!/usr/bin/env bash
# Installer for the extracted rust-panosmcp LXC package.
set -euo pipefail

# The script ships at <package>/packaging/lxc/install.sh, so the package root is
# two levels up — not the script's own directory. Getting this wrong makes the
# installer refuse a perfectly good archive with "package payload is missing
# bin/rust-panosmcp".
PACKAGE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
INSTALL_ROOT="${PANOSMCP_INSTALL_ROOT:-/}"
SERVICE_USER="${PANOSMCP_SERVICE_USER:-rust-panosmcp}"
SERVICE_GROUP="${PANOSMCP_SERVICE_GROUP:-rust-panosmcp}"
SKIP_USER_SETUP="${PANOSMCP_INSTALL_SKIP_USER:-0}"
SKIP_SYSTEMD_RELOAD="${PANOSMCP_INSTALL_SKIP_SYSTEMD_RELOAD:-0}"
FORCE_UNIT="${PANOSMCP_FORCE_UNIT:-0}"

fail() {
    echo ">> Installation refused: $*" >&2
    exit 1
}

target_path() {
    local relative="${1#/}"
    if [[ "$INSTALL_ROOT" == "/" ]]; then
        printf '/%s\n' "$relative"
    else
        printf '%s/%s\n' "${INSTALL_ROOT%/}" "$relative"
    fi
}

required_files=(
    bin/rust-panosmcp
    packaging/systemd/rust-panosmcp.service
    packaging/systemd/rust-panosmcp.sysusers
    packaging/systemd/rust-panosmcp.tmpfiles
    config/devices.example.json
)

# Validate the complete payload before creating users, directories, or files.
for relative in "${required_files[@]}"; do
    [[ -s "$PACKAGE_ROOT/$relative" ]] || fail "package payload is missing $relative"
done
[[ -x "$PACKAGE_ROOT/bin/rust-panosmcp" ]] \
    || fail "package binary is not executable: bin/rust-panosmcp"

[[ "$INSTALL_ROOT" == /* ]] || fail "PANOSMCP_INSTALL_ROOT must be an absolute path"
if [[ "$INSTALL_ROOT" != "/" && "$SKIP_USER_SETUP" != "1" ]]; then
    fail "a staged install requires PANOSMCP_INSTALL_SKIP_USER=1"
fi
if [[ "$SKIP_USER_SETUP" != "1" && "$EUID" -ne 0 ]]; then
    fail "run as root, or use PANOSMCP_INSTALL_SKIP_USER=1 for a staged smoke test"
fi

BIN_DIR="$(target_path /usr/local/bin)"
CONFIG_DIR="$(target_path /etc/rust-panosmcp)"
UNIT_DIR="$(target_path /etc/systemd/system)"
STATE_DIR="$(target_path /var/lib/rust-panosmcp)"
SYSUSERS_DIR="$(target_path /usr/lib/sysusers.d)"
TMPFILES_DIR="$(target_path /usr/lib/tmpfiles.d)"

# Create service user and directories via systemd-sysusers and systemd-tmpfiles.
if [[ "$SKIP_USER_SETUP" != "1" ]]; then
    command -v systemd-sysusers >/dev/null 2>&1 \
        || fail "systemd-sysusers is required for user/group creation"
    command -v systemd-tmpfiles >/dev/null 2>&1 \
        || fail "systemd-tmpfiles is required for directory creation"

    install -d -m 0755 "$SYSUSERS_DIR" "$TMPFILES_DIR"
    install -m 0644 "$PACKAGE_ROOT/packaging/systemd/rust-panosmcp.sysusers" \
        "$SYSUSERS_DIR/rust-panosmcp.conf"
    install -m 0644 "$PACKAGE_ROOT/packaging/systemd/rust-panosmcp.tmpfiles" \
        "$TMPFILES_DIR/rust-panosmcp.conf"

    systemd-sysusers rust-panosmcp.conf
    systemd-tmpfiles --create rust-panosmcp.conf
fi

install -d -m 0755 "$BIN_DIR" "$UNIT_DIR"

# Install the binary.
install -m 0755 "$PACKAGE_ROOT/bin/rust-panosmcp" "$BIN_DIR/rust-panosmcp"

# Check for site-customized unit and refuse to overwrite unless FORCE_UNIT=1.
SHIPPED_UNIT="$PACKAGE_ROOT/packaging/systemd/rust-panosmcp.service"
INSTALLED_UNIT="$UNIT_DIR/rust-panosmcp.service"
UNIT_CHANGED=0

if [[ -e "$INSTALLED_UNIT" ]]; then
    if ! cmp -s "$SHIPPED_UNIT" "$INSTALLED_UNIT"; then
        UNIT_CHANGED=1
    fi
fi

if [[ "$UNIT_CHANGED" -eq 1 && "$FORCE_UNIT" != "1" ]]; then
    echo ">> WARNING: Installed unit differs from shipped unit."
    echo ">> The installed unit at $INSTALLED_UNIT appears to be site-customized."
    echo ">> Skipping unit installation to preserve TLS paths, bind address, or --allowed-* flags."
    echo ">> The binary has been updated, but the service unit was NOT replaced."
    echo ">> To force unit replacement, re-run with PANOSMCP_FORCE_UNIT=1."
    echo ">> Otherwise, manually reconcile the shipped unit at:"
    echo ">>   $SHIPPED_UNIT"
    SKIP_UNIT_INSTALL=1
else
    install -m 0644 "$SHIPPED_UNIT" "$INSTALLED_UNIT"
    SKIP_UNIT_INSTALL=0
fi

# Install config example (not to the live filename).
install -d -m 0750 "$CONFIG_DIR"
if [[ -e "$PACKAGE_ROOT/config/devices.example.json" ]]; then
    install -m 0644 "$PACKAGE_ROOT/config/devices.example.json" \
        "$CONFIG_DIR/devices.json.example"
fi

# Create tokens.json only if absent, with strict 0600 permissions.
if [[ ! -e "$CONFIG_DIR/tokens.json" ]]; then
    printf '%s\n' '{"version":1,"tokens":[]}' >"$CONFIG_DIR/tokens.json"
    chmod 0600 "$CONFIG_DIR/tokens.json"
fi

# Ensure tokens.json has 0600 even on upgrade.
chmod 0600 "$CONFIG_DIR/tokens.json"

# If devices.json exists, ensure it has 0600.
if [[ -e "$CONFIG_DIR/devices.json" ]]; then
    chmod 0600 "$CONFIG_DIR/devices.json"
fi

# Never clobber mutation-state.json — it holds change-set audit trail.
# Leave it exactly alone if it exists.

if [[ "$SKIP_USER_SETUP" != "1" ]]; then
    chown "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR"
    if [[ -e "$CONFIG_DIR/tokens.json" ]]; then
        chown "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR/tokens.json"
    fi
    if [[ -e "$CONFIG_DIR/devices.json" ]]; then
        chown "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR/devices.json"
    fi
    if [[ -e "$CONFIG_DIR/devices.json.example" ]]; then
        chown "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR/devices.json.example"
    fi
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$STATE_DIR" 2>/dev/null || true
fi

if [[ "$INSTALL_ROOT" == "/" && "$SKIP_SYSTEMD_RELOAD" != "1" && "$SKIP_UNIT_INSTALL" != "1" ]]; then
    command -v systemctl >/dev/null 2>&1 || fail "systemctl is required for a live install"
    systemctl daemon-reload
fi

echo ">> rust-panosmcp package installed."
if [[ "$SKIP_UNIT_INSTALL" == "1" ]]; then
    echo ">> Binary updated; unit file was NOT replaced (site-customized)."
else
    echo ">> Binary and unit installed."
fi
echo ">> Next steps:"
echo ">>   1. Edit $CONFIG_DIR/devices.json (or copy from devices.json.example)"
echo ">>   2. Mint a bearer token: rust-panosmcp token add <name>"
echo ">>   3. systemctl enable --now rust-panosmcp.service"
echo ">> Endpoint: http://127.0.0.1:30031/mcp"
