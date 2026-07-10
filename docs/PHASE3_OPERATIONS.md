# Phase 3 guarded configuration operations

Phase 3 adds a deliberately narrow PAN-OS candidate lifecycle. Mutation is
disabled unless a device has an explicit `mutation` inventory block. Use a
dedicated PAN-OS XML API administrator whose key is not shared with people or
other automation.

## Inventory policy

Start from `config/devices.mutation.example.json`. The mutation block requires:

- `admin`: the exact PAN-OS administrator associated with the API key; partial
  commit and revert are restricted to changes PAN-OS attributes to this name;
- `allowed_xpath_roots`: one to 32 narrow subtrees below `/config`; `/config`
  itself is always refused;
- `allow_delete`: false by default; set true only when delete is required;
- `require_config_lock`: true by default and recommended. Stage must acquire a
  PAN-OS configuration lock before changing the candidate.

Changing any of these fields while an operation is active invalidates that
operation. SIGHUP retains operation state when the policy is unchanged.

## Token scopes

Every lifecycle tool requires an explicit tool name in the bearer token. A
wildcard tool scope remains read-only and never grants Phase 3 tools. A full
write lifecycle token normally needs:

```text
get_candidate_fingerprint
stage_panos_config
diff_panos_candidate
validate_panos_candidate
commit_panos_candidate
discard_panos_candidate
get_panos_operation
```

Unauthenticated HTTP is refused for mutation even in loopback development
mode. Local stdio is treated as the `local-stdio` principal. One token audit
identity owns the complete operation; external approval must authorize use of
that identity rather than switching tokens mid-operation.

## Required lifecycle

1. Call `get_candidate_fingerprint` for the device. The digest covers every
   operator-authorized candidate subtree in stable inventory order.
2. Call `stage_panos_config` with that exact fingerprint, one allowed XPath,
   and either:
   - `action: set` plus one bounded, DTD-free XML element; or
   - `action: delete`, no element, and exact confirmation `DELETE <xpath>`.
     Delete must also be enabled in inventory.
3. Keep the returned operation ID and new candidate fingerprint. Only that
   token principal can use the operation. One principal may have only one
   active operation per device.
4. Call `diff_panos_candidate`. PAN-OS produces the running/candidate change
   summary; output is capped at 256 KiB.
5. Call `validate_panos_candidate` with the operation ID and unchanged
   fingerprint. The server runs PAN-OS full validation and polls the job to a
   terminal state.
6. Only after successful validation, call `commit_panos_candidate` with the
   same operation ID and fingerprint. The server issues an admin-scoped partial
   commit and polls it to a terminal result.
7. Before commit, `discard_panos_candidate` performs an admin-scoped partial
   revert. It is fingerprint-bound and releases the configuration lock.

Every step rechecks operation ownership, device, inventory-policy signature,
and candidate fingerprint. v0.2 mutexes serialize by canonical management
endpoint, including multiple inventory aliases for one appliance.

## Cancellation and recovery

Once commit starts, it runs in a detached reconciliation worker. If the MCP
caller cancels or disconnects, the response reports `detached`; the worker
continues polling PAN-OS and writes a terminal audit event. Use
`get_panos_operation` to poll safe state and job ID.

A transport error or timeout after commit starts is recorded as
`indeterminate`; the server retains the operation and does not release its
configuration lock or permit discard. Reconcile the PAN-OS job and candidate
state manually before removing the lock. A terminal PAN-OS commit failure is
recorded as `failed` and remains eligible for explicit discard.

With `--state-file`, operation and change-set records survive process restart.
A restart converts staging, validating, or committing records to
`indeterminate`; the endpoint remains blocked until manual reconciliation.
Without that option, v0.1 in-memory recovery behavior remains. After an
unexpected restart, do not blindly retry a stage or commit. Inspect the
PAN-OS job list, candidate change summary, commit locks, and configuration
locks. Reconcile any running job, then use PAN-OS admin-scoped partial revert
or commit under change control. Remove a stale configuration lock only after
confirming no lifecycle worker remains. With the service stopped, use the
v0.2 `state resolve` command documented in `V0.2_CHANGE_SETS.md` to record the
proven terminal outcome and unblock the endpoint.

Audit events contain principal, device, operation ID, action, SHA-256 XPath
fingerprint, job ID, outcome, and duration. They exclude XPath text, XML
elements, configuration output, bearer values, and PAN-OS keys.

## Isolation boundary

PAN-OS 12.1.5 lab acceptance confirmed lock acquisition, full validation,
admin-scoped partial commit, and a committed add/delete cleanup round trip. The
server therefore claims:

- deterministic serialization among its own calls;
- drift refusal inside every authorized mutation subtree;
- cross-administrator exclusion while PAN-OS honors the held configuration
  lock; and
- commit/revert filtering by the configured PAN-OS admin.

It does not claim isolation from another process using the same PAN-OS admin
identity. A dedicated, unshared admin is mandatory. Administrators with
privilege to remove locks or commit for other admins remain outside this trust
boundary.
