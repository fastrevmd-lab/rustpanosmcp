# PAN-OS compatibility

The v0.1 XML API surface targets standalone firewalls in the PAN-OS 10.2,
11.1, 11.2, and 12.1 release families. Panorama, commit-all, multi-vsys, and
HA-aware behavior remain out of scope. Vendor support status and model support
change independently; operators must confirm both before deploying.

| Release family | Parser/mock CI | Read lab | Guarded mutation lab |
|---|---:|---:|---:|
| PAN-OS 10.2 | yes | not yet recorded | not yet recorded |
| PAN-OS 11.1 | yes | not yet recorded | not yet recorded |
| PAN-OS 11.2 | yes | not yet recorded | not yet recorded |
| PAN-OS 12.1 | yes | 12.1.5 | 12.1.5 |

`rust-panosmcp-core/tests/panos_version_matrix.rs` validates representative
system-info envelopes for every selected family on each CI run. That proves
parser compatibility, not device compatibility. The opt-in
`scripts/test-panos-matrix.sh` runs the strict-HTTPS read client and complete
MCP path against each configured real firewall. Mutation remains a separate,
explicitly gated disposable-lab test.

Configure any available labs without placing credentials in the repository:

```bash
export PANOS_MATRIX_11_2_INVENTORY=/secure/11.2/devices.json
export PANOS_MATRIX_11_2_DEVICE=lab-11-2
export PANOS_MATRIX_12_1_INVENTORY=/secure/12.1/devices.json
export PANOS_MATRIX_12_1_DEVICE=lab-12-1
scripts/test-panos-matrix.sh
```

Before adding a row or changing a claim, capture the exact maintenance release,
run both read suites, and—only on a disposable candidate—run the Phase 3
reversible add/delete workflow. A maintenance upgrade does not inherit the
previous row automatically.

Primary vendor release documentation:

- https://docs.paloaltonetworks.com/pan-os
- https://docs.paloaltonetworks.com/compatibility-matrix/reference/supported-os-releases-by-model/palo-alto-networks-appliances
