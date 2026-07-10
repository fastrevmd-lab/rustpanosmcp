#!/usr/bin/env bash
# Run opt-in read acceptance across configured PAN-OS release-family labs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

families=(10_2 11_1 11_2 12_1)
configured=0
for family in "${families[@]}"; do
    inventory_var="PANOS_MATRIX_${family}_INVENTORY"
    device_var="PANOS_MATRIX_${family}_DEVICE"
    inventory="${!inventory_var:-}"
    device="${!device_var:-}"
    if [[ -z "$inventory" && -z "$device" ]]; then
        continue
    fi
    if [[ -z "$inventory" || -z "$device" ]]; then
        echo "$inventory_var and $device_var must be set together" >&2
        exit 1
    fi
    configured=$((configured + 1))
    echo ">> PAN-OS ${family//_/.}: read client and full MCP path"
    PANOS_LAB_INVENTORY="$inventory" PANOS_LAB_DEVICE="$device" \
        cargo test --locked -p rust-panosmcp-core --test lab_firewall \
        -- --ignored --nocapture
    PANOS_LAB_INVENTORY="$inventory" PANOS_LAB_DEVICE="$device" \
        cargo test --locked -p rust-panosmcp --test lab_mcp_firewall \
        -- --ignored --nocapture
done

if [[ "$configured" -eq 0 ]]; then
    echo "no PAN-OS matrix labs configured" >&2
    echo "set PANOS_MATRIX_<MAJOR>_<MINOR>_INVENTORY and _DEVICE" >&2
    exit 2
fi
