# PAN-OS compatibility

The v0.1 XML API surface targets standalone firewalls in the PAN-OS 10.2,
11.1, 11.2, 12.1, and 12.2 release families. Panorama, commit-all, multi-vsys,
and HA-aware behavior remain out of scope. Vendor support status and model
support change independently; operators must confirm both before deploying.

| Release family | Parser/mock CI | Read lab | Guarded mutation lab |
|---|---:|---:|---:|
| PAN-OS 10.2 | yes | not yet recorded | not yet recorded |
| PAN-OS 11.1 | yes | not yet recorded | not yet recorded |
| PAN-OS 11.2 | yes | not yet recorded | not yet recorded |
| PAN-OS 12.1 | yes | 12.1.5 | 12.1.5 |
| PAN-OS 12.2 | yes | not yet recorded | not yet recorded |

## CVE-2026-0310 version floor

`gather_device_facts` compares the reported `sw-version` against the
published fix levels for CVE-2026-0310 and returns a non-empty `advisories`
list when the device is below its train's fix level. This is advisory only:
per the house rule, it never blocks a call or changes device state, and a
human must act on it.

| Release family | Fix level |
|---|---|
| PAN-OS 10.2 | 10.2.18-h10 |
| PAN-OS 11.1 | 11.1.16-h2 |
| PAN-OS 11.2 | 11.2.13-h2 |
| PAN-OS 12.1 | 12.1.10 |
| PAN-OS 12.2 | 12.2.3 |

PAN-OS 10.1 and 11.0 are no longer supported release families and have no fix
level tracked here; a device reporting one of those trains gets no advisory
from this table, which is not a claim that it is unaffected.

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
