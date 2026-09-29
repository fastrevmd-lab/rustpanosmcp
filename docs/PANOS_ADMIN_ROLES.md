<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/mechub-mark.svg">
    <img src="assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">rust-panosmcp</h1>

<p align="center"><strong>PAN-OS least-privilege administrator roles</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

> **Unofficial / community project.** This is an independent community project
> and does not claim affiliation with or endorsement by Palo Alto Networks.
> Product names and trademarks are used only to identify the systems with which
> the software interoperates.

This is a role guide for the **PAN-OS administrator accounts** rust-panosmcp
authenticates as — the API key holders on the firewall itself. It is distinct
from the MCP bearer-token roles that gate *this server's* tools, which are
covered in [MCP_ROLE_WORKFLOW.md](MCP_ROLE_WORKFLOW.md). The two layers are
independent and both matter: an MCP reader token calling through a PAN-OS
account that can commit configuration is still a firewall with a
change-capable credential sitting behind a read-only prompt.

## Two PAN-OS accounts, not one

Provision exactly two PAN-OS administrator accounts per firewall (or per
Panorama-managed group), each with its own API key, and map them to the
matching rust-panosmcp inventory entries and MCP bearer scopes:

| PAN-OS account | Custom admin role | Used by | Never gets |
|---|---|---|---|
| `mcp-reader` | Read-only: enable only the *Operational Requests* and *Configuration* (read) XML API categories under Admin Roles; PAN-OS's XML API role scoping is coarse-grained by category, not per command, so this is the widest surface the account can reach. No commit, no config write. | The reader MCP connection (`list_devices`, `gather_device_facts`, `execute_panos_op`, `get_panos_config`) | Config write privilege, Commit privilege, superuser |
| `mcp-change` | Write: candidate configuration read/write and commit, scoped to the exact XPath roots this deployment's `mutation.allowed_xpath_roots` covers. No access to accounts, roles, HA, or system settings beyond what the automation touches. | The writer MCP connection (`create_panos_change_set`, `stage_panos_config`, `commit_panos_candidate`, …) | Superuser, access to Device/Network tabs outside the automated scope |

Build each with PAN-OS **Admin Roles** (Device > Admin Roles), starting from
no access and enabling only the specific XML API categories and
GUI/CLI privileges each account needs — not by cloning the built-in
`superuser` role and removing items. A denylist role silently regains
access when PAN-OS adds a new privilege in a future release; an allowlist
role does not.

The PAN-OS admin role is the *coarse*, per-account gate: it grants or
withholds entire XML API categories (Operational Requests, Configuration,
Commit, …), not individual commands. The server layers a second, structural
gate on top of that for `execute_panos_op`
(`validate_read_only_op_command` in `rust-panosmcp-core/src/xml.rs`): the
submitted command must parse as exactly one `<show>` root element, carry no
attributes on that root, and fit within a size and nesting-depth limit. This
rejects malformed or non-`<show>` XML outright, but it is not a per-command
or per-device allowlist — any well-formed `<show>...</show>` body passes it,
so within that shape the PAN-OS admin role above is the only thing deciding
which specific operational commands the account may actually run. Do not
treat the server-side check as a substitute for scoping the PAN-OS role
tightly.

Rationale for splitting rather than sharing one account across both MCP
connections:

- **Blast radius.** A leaked or misused reader API key can, at most, read
  configuration and operational state. It cannot stage, approve, or commit
  anything, regardless of what the MCP transport layer's bearer scopes claim
  — the PAN-OS role is the second, independent gate on top of
  rust-panosmcp's own [MCP_ROLE_WORKFLOW.md](MCP_ROLE_WORKFLOW.md) approval
  chain. Two-person control at the MCP layer is not two-person control if
  both the writer and the reviewer ultimately execute against the same
  all-powerful PAN-OS account.
- **Attribution.** PAN-OS administrator logs (`show log system`, config
  audit) attribute every action to the PAN-OS account, not to the MCP
  bearer token. One account per capability keeps that log directly useful
  during an incident instead of requiring you to cross-reference
  rust-panosmcp's own audit trail to know which MCP connection issued a
  given PAN-OS-side action.
- **Rotation blast radius.** Rotating the change account's key (a
  higher-value credential) is unrelated to, and does not require touching,
  the reader account's key.

## Restrict source IPs on the management interface

Independently of the PAN-OS account split, restrict which addresses may
reach the PAN-OS management plane at all:

- On the management interface itself (Device > Setup > Interfaces >
  Management), set **Permitted IP Addresses** to the exact host or narrow
  CIDR range rust-panosmcp runs from. An API key is only as good as the
  network path that can present it; a key with no source-IP restriction is
  usable from anywhere it leaks to.
- If rust-panosmcp and PAN-OS sit on different networks, prefer a
  dedicated management VLAN or jump path with its own restrictive ACL over
  widening the permitted-IP list.
- If the deployment moves rust-panosmcp (new host, new container IP,
  failover), update the permitted-IP list as part of that change, not
  after — an unreachable-until-updated management interface fails safe;
  a permanently wide one does not.
- This is defense in depth, not a substitute for TLS trust pinning or
  short-lived, narrowly-scoped API keys. Combine it with the
  [PAN-OS API-key lifetime and rotation](OPERATIONS.md#pan-os-api-key-lifetime-and-rotation)
  guidance.

## Verifying the split

After provisioning both accounts:

1. Confirm each inventory device entry's `api_key` points at the intended
   account's key (`config/devices.example.json` documents the `env`/`file`
   source shapes).
2. Call `gather_device_facts` through the reader MCP connection and confirm
   PAN-OS logs attribute it to `mcp-reader`.
3. Attempt a mutation tool through the reader MCP connection and confirm it
   is refused at the MCP layer (see
   [MCP_ROLE_WORKFLOW.md](MCP_ROLE_WORKFLOW.md)) — then, as a second
   independent check, confirm the `mcp-reader` PAN-OS account's admin role
   has no commit or config-write privilege, so even a misconfigured MCP
   scope cannot reach PAN-OS as a write.
4. Run `gather_device_facts` through each account's MCP connection, *then*
   confirm `GET /readyz` is healthy (see
   [OPERATIONS.md](OPERATIONS.md#pan-os-api-key-lifetime-and-rotation)).
   `/readyz`'s `panos_auth` check is reactive, not an active poll: it only
   reflects the outcome of the most recent real request to each device, so
   checking it before any request has been made proves nothing about
   whether the account's key actually works. Also confirm that connecting
   from outside the permitted management-IP range is refused by PAN-OS.
