# README Quickstart Workflow Link Design

**Date:** 2026-07-13
**Status:** Approved for specification review

## Context

The README already links to `docs/MCP_ROLE_WORKFLOW.md`, but the link is buried
inside the long Status section. Status also appears before Quick start, which
keeps installation and startup guidance farther from the top of the document.

## Goals

- Move the complete `## Status` section immediately below `## Quick start`.
- End Quick start with a visible link to the MCP role workflow guide.
- Keep the guide link in one place so readers have one clear next step.
- Preserve all other README content and section ordering.

## Non-goals

- Do not change the workflow guide itself.
- Do not rewrite release status, installation, configuration, or security text.
- Do not change project behavior, packaging, or tests.

## Design

Quick start will retain its existing Installation, stdio, and Streamable HTTP
instructions. After its final operations-reference paragraph, add this callout:

> Next: [Learn the reader, writer, and reviewer MCP role workflow](../../MCP_ROLE_WORKFLOW.md).

In the README, the actual relative target will be
`docs/MCP_ROLE_WORKFLOW.md`; the adjusted target above is only for this design
document's location.

The existing Status section will move without content changes to the position
between that callout and `## MCP tools reference`. Its current workflow-guide
sentence will be removed because the new Quick start callout replaces it.

The resulting top-level sequence will be:

1. Introductory project material
2. Workspace
3. Quick start
4. Status
5. MCP tools reference
6. Remaining existing sections

## Data Flow and Failure Handling

This is a static Markdown navigation change. A reader completes Quick start,
encounters the workflow callout, and can open the repository-relative guide.
If the target file is missing or the relative path is wrong, verification must
fail before the change is considered complete.

## Verification

- Confirm `## Quick start` appears before `## Status` and `## Status` appears
  before `## MCP tools reference`.
- Confirm the workflow callout is the final content in Quick start.
- Confirm `docs/MCP_ROLE_WORKFLOW.md` exists.
- Confirm the README contains exactly one link to that guide.
- Run `git diff --check` and the workspace test suite.
