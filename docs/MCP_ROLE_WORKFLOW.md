<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/mechub-mark.svg">
    <img src="assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">rust-panosmcp</h1>

<p align="center"><strong>MCP role workflow</strong><br>
<em>Reader · Writer · Reviewer</em><br>
<em>a mechub project — sovereign network-security automation</em></p>

> **Unofficial / community project.** This is an independent community project
> and does not claim affiliation with or endorsement by Palo Alto Networks.
> Product names and trademarks are used only to identify the systems with which
> the software interoperates.

This guide is a concise operating reference for PAN-OS engineers using the
role-separated rust-panosmcp connections. It assumes the MCP endpoint,
inventory, PAN-OS API administrator, and bearer identities are already
configured. For installation and credential administration, use the linked
operator runbooks rather than placing secrets in prompts.

## Connection model

The three connections normally point to the same rust-panosmcp endpoint. Their
bearer identities enforce different device and tool scopes.

| Connection | Responsibility | Must not do |
|---|---|---|
| `rust-panosmcp` | List authorized devices, gather facts, execute bounded `<show>` commands, and read running or candidate configuration | Plan, approve, apply, validate, commit, or discard changes |
| `rust-panosmcp-writer` | Fingerprint candidate state; create and apply approved change sets; diff, validate, commit, discard, and poll owned operations | Approve its own plan or use the legacy unapproved stage path |
| `rust-panosmcp-reviewer` | Retrieve an exact persisted change set and approve its digest independently | Fingerprint, apply, validate, commit, discard, or otherwise mutate PAN-OS |

Configured connection names may differ, but the separation of bearer
principals must remain. Keep writer and reviewer credentials in separate
operator contexts.

```text
read → fingerprint → plan → independent review → apply to candidate
     → diff → full validation → commit or discard
```

The approval digest binds the writer identity, device, initial candidate
fingerprint, and ordered actions. Approval expires 15 minutes after planning
and can be used once. Any bound-field change requires a new plan and a new
independent approval.

## 1. Reader connection

Use the reader for inventory discovery and operational evidence. Reader calls
do not create mutation state.

### Discover authorized devices

```text
Using only rust-panosmcp, list the PAN-OS devices this reader is authorized to
access. Return each exact inventory name and safe metadata.
```

Use the returned exact inventory name as `<device-name>` in later prompts.

### Gather device facts

```text
Using only rust-panosmcp, gather device facts for <device-name>. Return the
hostname, model, serial number, PAN-OS version, management IP, and uptime.
Do not use either privileged connection.
```

### Execute a read-only operational command

```text
Using only rust-panosmcp, run this read-only operational command on
<device-name>:

<show><system><info/></system></show>

Return the bounded result and state whether byte or line limits truncated it.
```

`execute_panos_op` accepts one XML command rooted at `<show>`. It does not
accept configuration-changing XML.

### Read PAN-OS configuration

```text
Using only rust-panosmcp, read the running configuration for <device-name> at
the validated XPath /config/.... Limit the result to 200 lines, report any
truncation, and do not use either privileged connection.
```

Replace `/config/...` with the exact validated XPath required by the change or
investigation. Select `candidate` instead of `running` only when candidate
state is intentionally required.

> **Stop condition:** Reader evidence is complete. Do not move to the writer
> unless an authorized change request exists with a narrow target XPath and
> exact intended XML actions.

## 2. Writer connection: fingerprint and plan

The writer first binds the proposed actions to observed candidate state. Plan
creation persists an immutable change set; it does not change PAN-OS.

### Observe the candidate fingerprint

```text
Using only rust-panosmcp-writer, get the candidate fingerprint for
<device-name>. Return the exact fingerprint. Do not create or apply a change
set.
```

Preserve the returned `<fingerprint>` as the plan's initial candidate
fingerprint.

### Review the proposed action before persistence

The following documentation-only example adds one address object. Replace the
XPath, object name, value, and description with the approved change request.

```text
Using only rust-panosmcp-writer, prepare—but do not create or apply—a change
set for <device-name> using initial candidate fingerprint <fingerprint>.

Ordered action 1:
- action: set
- XPath: /config/...
- element: <entry name="example-address"><ip-netmask>192.0.2.10/32</ip-netmask><description>Documentation example</description></entry>

Reproduce the exact ordered action. Check the XML and XPath for structural
correctness and alignment with the authorized change request. State that
server authorization is not yet verified. Stop without changing server or
PAN-OS state.
```

No read-only tool exposes the token mutation grant or inventory mutation roots;
creation-time policy enforcement by `create_panos_change_set` is authoritative.
An operator must not infer or broaden scope to bypass a refusal.

`192.0.2.10/32` is an IANA documentation address, not a production value.

### Create the immutable plan

After the proposed action matches the approved change request:

```text
Using only rust-panosmcp-writer, create the exact change set just reviewed for
<device-name> using initial candidate fingerprint <fingerprint>.

Return:
- change-set ID;
- exact digest;
- initial candidate fingerprint;
- ordered actions, including each XPath and XML element;
- owner;
- state; and
- approval expiration.

Do not apply the change set and do not use stage_panos_config.
```

Preserve `<change-set-id>`, `<digest>`, `<fingerprint>`, the exact ordered
actions, and the expiration for the reviewer handoff.

> **Stop condition:** The plan exists, but PAN-OS candidate state is unchanged.
> Transfer the plan identifiers and approved change request to an independent
> reviewer context. The writer must not approve its own plan.

## 3. Reviewer connection: inspect and approve

The reviewer validates the persisted object, not a summary supplied by the
writer. Review and approval should be separate prompts so human authorization
is explicit.

### Retrieve and inspect the exact plan

```text
Using only rust-panosmcp-reviewer, retrieve change set <change-set-id> for
<device-name>.

Compare its owner, initial candidate fingerprint, ordered XPath/XML actions,
digest, state, and expiration with the approved change request already provided
in this independent reviewer context.

Report every match or discrepancy. Do not approve the change set.
```

Reject the plan when the device, fingerprint, action order, XPath, XML element,
digest, owner, or expiry is unexpected. Do not ask the writer to edit a
persisted plan; create and review a new one.

### Approve the reviewed digest

Only after the human reviewer authorizes the exact retrieved plan:

```text
Using only rust-panosmcp-reviewer, approve change set <change-set-id> for
<device-name> using exact expected digest <digest>.

Return the resulting state, approver identity, digest, and expiration. Do not
call any writer tool.
```

Self-approval and digest mismatch are refused by the server.

> **Stop condition:** The exact plan is independently approved and unexpired.
> Return `<change-set-id>`, `<digest>`, and the original `<fingerprint>` to the
> writer context. Approval alone does not change PAN-OS.

## 4. Writer connection: apply, diff, validate, and finish

The original writer principal applies the approved plan. Apply changes PAN-OS
candidate configuration under the configured serialization and lock policy; it
does not change running configuration.

### Apply and inspect the candidate diff

```text
Using only rust-panosmcp-writer, apply approved change set <change-set-id> for
<device-name> using exact digest <digest> and initial candidate fingerprint
<fingerprint>.

Return the operation ID and post-apply candidate fingerprint. Then retrieve
the candidate diff for that operation using the post-apply fingerprint.
Summarize the diff and stop. Do not validate or commit.
```

Preserve `<operation-id>` and the returned post-apply `<fingerprint>` for every
remaining lifecycle call.

If the diff is incorrect, skip validation and use the discard path below.

### Run full PAN-OS validation

After an operator accepts the exact candidate diff:

```text
Using only rust-panosmcp-writer, fully validate operation <operation-id> for
<device-name> using post-apply candidate fingerprint <fingerprint>.

Return the validation job ID, terminal result, details, and commit-eligible
fingerprint. Do not commit.
```

Validation must succeed for the unchanged fingerprint before commit is
eligible.

### Commit after explicit authorization

After the human operator authorizes the validated candidate:

```text
Using only rust-panosmcp-writer, commit operation <operation-id> for
<device-name> using the validated candidate fingerprint <fingerprint>.

Return the disposition, PAN-OS job ID, terminal success when known, and
details. If reconciliation is detached, poll get_panos_operation until the
server records a terminal state. Do not retry the commit blindly.
```

Commit uses the configured PAN-OS administrator's scoped partial commit.

### Discard instead of commit

Before commit, discard an unacceptable candidate operation with:

```text
Using only rust-panosmcp-writer, discard operation <operation-id> for
<device-name> using post-apply candidate fingerprint <fingerprint>.

Return the resulting candidate fingerprint and confirm whether the operation
state is discarded. Do not commit.
```

Discard performs an administrator-scoped partial candidate revert and releases
the configuration lock only after PAN-OS accepts the unlock transition.

> **Stop condition:** Finish only when the operation reports a proven terminal
> state and the expected lock state. An `indeterminate` record requires manual
> PAN-OS job, candidate, administrator-attribution, and lock reconciliation.

## Handoff record

Keep these exact values in the controlled change record:

| Stage | Required evidence |
|---|---|
| Plan | Device, owner, initial fingerprint, ordered actions, change-set ID, digest, expiration |
| Approval | Reviewer identity, exact digest, approval state, expiration |
| Apply | Operation ID, post-apply candidate fingerprint, candidate diff |
| Validate | Validation job ID, terminal result, commit-eligible fingerprint |
| Commit/discard | Disposition, job ID when applicable, terminal state, resulting fingerprint, lock outcome |

Do not place bearer credentials, PAN-OS API keys, or unredacted sensitive
configuration in the change record.

## Troubleshooting

| Symptom | Meaning | Operator response |
|---|---|---|
| HTTP 401 | Bearer credential is missing, malformed, invalid, revoked, or expired | Reissue or rotate the correct least-privilege identity and reload the service; never paste the bearer value into a prompt or ticket |
| HTTP 403 | The authenticated identity lacks the exact tool or device scope | Confirm the selected reader/writer/reviewer connection and requested inventory name; do not broaden scope merely to bypass the refusal |
| Pre-apply fingerprint refusal | Candidate state changed before an operation was created | Inspect current candidate state, obtain a fresh fingerprint, and create and independently approve a new plan; do not reuse stale identifiers |
| Post-apply operation fingerprint refusal | Candidate state differs from the fingerprint recorded after staging/apply | Stop new plans and retries; inspect the existing operation, candidate changes, administrator attribution, PAN-OS jobs, and lock state; reconcile or discard the existing operation only when eligible, and do not create/apply another plan until it is terminal and its lock state is resolved |
| Approval expired | The 15-minute plan approval window elapsed | Create a new plan and repeat independent review and approval |
| Detached commit | Commit reconciliation continues after the caller disconnected or cancelled | Poll `get_panos_operation` with the original writer identity |
| Indeterminate operation | The server cannot prove a terminal PAN-OS outcome | Stop retries and follow manual PAN-OS job, candidate, attribution, and lock reconciliation procedures |

## Operator references

- [Phase 2 authentication and remote transport](PHASE2_OPERATIONS.md)
- [Phase 3 guarded candidate lifecycle](PHASE3_OPERATIONS.md)
- [v0.2 change sets and independent approval](V0.2_CHANGE_SETS.md)
- [Production operations and recovery](OPERATIONS.md)
- [Threat model](../THREAT_MODEL.md)
