# rust-panosmcp role workflow guide design

## Objective

Add a polished, repository-native Markdown reference that teaches experienced
PAN-OS engineers how to use rust-panosmcp's reader, writer, and reviewer MCP
connections. The guide must make the approval boundary and candidate lifecycle
easy to follow without relying on lab-specific names or credentials.

## Audience and tone

The primary audience is an experienced PAN-OS engineer who understands PAN-OS
operational commands, candidate configuration, XPath, validation, and commit
jobs, but may be new to rust-panosmcp and MCP tool routing.

The writing will be concise and operational. It will explain rust-panosmcp
concepts that affect safe use, while avoiding introductory PAN-OS material.
Natural-language prompt templates will be copy-ready and use explicit stop
conditions.

## Deliverables

1. Add `docs/MCP_ROLE_WORKFLOW.md` as the branded operator reference.
2. Add a discoverability link to the existing documentation paragraph in
   `README.md`.
3. Reuse the existing Mechub SVG assets; add no new image assets.

No runtime code, configuration, token, inventory, or deployment behavior will
change.

## Document structure

The guide will use a role-oriented structure because the security handoffs are
more important than an alphabetical tool catalog.

### Brand header

The opening will follow the README's established presentation:

- centered light/dark Mechub mark using the existing assets through
  guide-relative paths `assets/mechub-mark-light.svg` and
  `assets/mechub-mark.svg`;
- centered `rust-panosmcp` title;
- concise subtitle identifying the reader, writer, and reviewer workflow;
- the repository's independent-community-project disclaimer.

### Orientation

The first content section will contain:

- a connection matrix mapping reader, writer, and reviewer identities to their
  responsibilities and prohibited actions;
- a compact lifecycle showing
  `read -> plan -> review -> apply -> diff -> validate -> commit/discard`;
- a statement that the roles normally point to the same MCP endpoint and are
  separated by bearer identity, device scope, and tool scope.

### Four-part workflow

The main guide will preserve the requested four-part training sequence.

1. **Reader connection**
   - list authorized devices;
   - gather device facts;
   - run one read-only XML command rooted at `<show>`;
   - read bounded running or candidate configuration;
   - use generic `<device-name>` and `/config/...` placeholders.

2. **Writer connection: plan**
   - retrieve the candidate fingerprint;
   - prepare and create an ordered change set without changing PAN-OS;
   - return and preserve the change-set ID, digest, initial fingerprint,
     ordered actions, and expiry;
   - stop before applying the plan.

3. **Reviewer connection: inspect and approve**
   - retrieve the persisted plan independently;
   - compare its owner, device, fingerprint, ordered XPath/XML actions, digest,
     and expiry with the approved change request;
   - stop for human authorization before approval;
   - approve only the exact digest and explain that any edit requires a new
     plan and approval.

4. **Writer connection: execute**
   - apply the approved digest and initial fingerprint within the approval
     window;
   - preserve the returned operation ID and new candidate fingerprint;
   - inspect the diff, then stop;
   - run full validation, then stop;
   - commit only after explicit authorization, or discard when the candidate
     is not acceptable;
   - poll `get_panos_operation` when commit reconciliation is detached.

Each part will include a short purpose statement, exact connection name pattern,
copy-ready prompt templates, expected handoff fields, and a clear stop
condition.

## Safety model

The guide will reinforce the implemented controls without implying broader
guarantees:

- writer and reviewer are separate bearer principals;
- the writer cannot approve its own change set;
- the reviewer cannot fingerprint, apply, validate, commit, or discard;
- the writer connection omits the legacy `stage_panos_config` tool so the
  approval layer is not bypassed;
- wildcard tool scope remains read-only;
- approval is bound to the owner, device, initial candidate fingerprint, and
  ordered actions, and expires 15 minutes after planning;
- apply changes the candidate, not the running configuration;
- every later lifecycle step is bound to the returned operation ID and exact
  fingerprint;
- configuration locks, detached reconciliation, and indeterminate recovery
  are referenced accurately without duplicating the full operator runbooks.

Examples will use documentation-only values and placeholders. The guide will
not contain real endpoints, device aliases, bearer values, API keys, serial
numbers, management addresses, or production configuration.

## Troubleshooting reference

A short final section will distinguish the most actionable boundary failures:

- HTTP 401: missing, invalid, revoked, or expired bearer credential;
- HTTP 403: authenticated identity lacks the requested exact tool or device
  scope;
- drift/fingerprint refusal: candidate state changed after observation;
- expired approval: create and independently approve a new plan;
- detached or indeterminate operation: poll safe operation state or follow the
  manual reconciliation runbook rather than retrying blindly.

This section will link to `PHASE2_OPERATIONS.md`, `PHASE3_OPERATIONS.md`, and
`V0.2_CHANGE_SETS.md` for full procedures.

## README integration

Add one link to `docs/MCP_ROLE_WORKFLOW.md` in the README paragraph that already
routes users to acceptance, operations, compatibility, benchmark, and security
documentation. The README will remain a project overview rather than duplicate
the guide.

## Verification

Documentation verification will include:

1. `git diff --check` for whitespace and patch integrity.
2. A relative-link check for every local path added to the guide and README.
3. A scan for unresolved planning markers or template placeholders outside the
   intentional `<device-name>`, `<change-set-id>`, `<digest>`, `<fingerprint>`,
   and `<operation-id>` prompt variables.
4. A scan ensuring no bearer token, API-key value, real endpoint, or lab-specific
   device identifier was introduced.
5. Markdown inspection confirming the four numbered workflow sections, role
   matrix, stop conditions, troubleshooting reference, and brand header are all
   present.

Because implementation changes documentation only, the verified clean baseline
build and workspace test suite provide the code baseline; implementation
verification will focus on the changed Markdown and links.

## Out of scope

- Installing or configuring MCP clients.
- Issuing, rotating, or storing bearer credentials.
- Configuring PAN-OS API administrators or inventory mutation roots.
- Teaching general PAN-OS XML API or XPath fundamentals.
- Adding generated HTML, PDF, screenshots, diagrams, or new brand artwork.
- Changing runtime tools, authorization, approval policy, or mutation behavior.
