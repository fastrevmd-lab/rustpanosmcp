# README Quickstart Workflow Link Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reorder the README so Quick start precedes Status and ends with one visible link to the MCP role workflow guide.

**Architecture:** This is one atomic Markdown navigation change in `README.md`. Move the existing Status block below Quick start, replace its buried workflow reference with a dedicated Quick start callout, and verify the heading order and repository-relative link mechanically.

**Tech Stack:** GitHub-flavored Markdown, Bash checks, ripgrep, Cargo workspace tests

## Global Constraints

- Move the complete `## Status` section immediately below `## Quick start`.
- End Quick start with a visible link to the MCP role workflow guide.
- Keep the guide link in one place so readers have one clear next step.
- Preserve all other README content and section ordering.
- Do not change `docs/MCP_ROLE_WORKFLOW.md`.
- Do not rewrite release status, installation, configuration, or security text.
- Do not change project behavior, packaging, or tests.

---

### Task 1: Reorder README navigation and expose the workflow guide

**Files:**
- Modify: `README.md:26-198`
- Reference only: `docs/MCP_ROLE_WORKFLOW.md`

**Interfaces:**
- Consumes: the existing `## Status`, `## Quick start`, and `## MCP tools reference` sections
- Produces: top-level order `## Workspace` → `## Quick start` → `## Status` → `## MCP tools reference`, with exactly one README link to `docs/MCP_ROLE_WORKFLOW.md`

- [ ] **Step 1: Run the structural check against the current README**

```bash
quick_start=$(rg -n '^## Quick start$' README.md | cut -d: -f1)
status=$(rg -n '^## Status$' README.md | cut -d: -f1)
tools=$(rg -n '^## MCP tools reference$' README.md | cut -d: -f1)
test "$quick_start" -lt "$status"
test "$status" -lt "$tools"
```

Expected: the first comparison fails because Status currently appears before Quick start.

- [ ] **Step 2: Move Status and add the Quick start callout**

Use `apply_patch` to make these exact transformations in `README.md`:

1. Move the entire block beginning at `## Status` and ending immediately before
   `## Workspace` to the position immediately before `## MCP tools reference`.
2. In the moved Status block, replace:

```markdown
Phase 4 release evidence is in
[docs/PHASE4_ACCEPTANCE.md](docs/PHASE4_ACCEPTANCE.md). The role-separated
reader, writer, and reviewer workflow is in
[docs/MCP_ROLE_WORKFLOW.md](docs/MCP_ROLE_WORKFLOW.md). Production deployment,
```

with:

```markdown
Phase 4 release evidence is in
[docs/PHASE4_ACCEPTANCE.md](docs/PHASE4_ACCEPTANCE.md). Production deployment,
```

3. Immediately after the final Quick start paragraph and before the moved
   `## Status` heading, add:

```markdown
> Next: [Learn the reader, writer, and reviewer MCP role
> workflow](docs/MCP_ROLE_WORKFLOW.md).

```

- [ ] **Step 3: Verify heading order, callout placement, and link uniqueness**

```bash
quick_start=$(rg -n '^## Quick start$' README.md | cut -d: -f1)
status=$(rg -n '^## Status$' README.md | cut -d: -f1)
tools=$(rg -n '^## MCP tools reference$' README.md | cut -d: -f1)
test "$quick_start" -lt "$status"
test "$status" -lt "$tools"
test "$(rg -o 'docs/MCP_ROLE_WORKFLOW\.md' README.md | wc -l)" -eq 1
test -f docs/MCP_ROLE_WORKFLOW.md
awk '/^## Quick start$/{inside=1; next} /^## /{if (inside) exit} inside{print}' README.md \
  | sed '/^[[:space:]]*$/d' \
  | tail -n 2 \
  | diff -u - <(printf '%s\n' \
      '> Next: [Learn the reader, writer, and reviewer MCP role' \
      '> workflow](docs/MCP_ROLE_WORKFLOW.md).')
```

Expected: exit 0; the callout is the final nonblank Quick start content and the guide target exists exactly once in the README.

- [ ] **Step 4: Review the focused Markdown diff**

```bash
git diff -- README.md
git diff --check
```

Expected: Status is moved without release-text rewrites, the old buried workflow sentence is gone, the callout is present, and `git diff --check` exits 0.

- [ ] **Step 5: Run the workspace test suite**

```bash
cargo test --workspace --locked
```

Expected: all non-environmental tests pass; lab and manual benchmark tests remain intentionally ignored.

- [ ] **Step 6: Commit the README change**

```bash
git add README.md
git commit -m "docs: surface MCP workflow after Quick start"
```

Expected: one documentation commit containing only `README.md`.
