# Dependency PR Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve every open Dependabot PR while preserving Rust 1.88 MSRV policy, repairing compatible dependency updates, and leaving `main` green with no open dependency PRs.

**Architecture:** Merge already-green, policy-compatible updates as their own squash commits so GitHub retains each dependency's audit trail. Consolidate the two repairable failed Cargo updates and Dependabot policy exclusions in `agent/dependency-maintenance`, validate both workspace and fuzz lockfiles, and merge that branch through one reviewed PR. Close policy-incompatible or superseded Dependabot PRs with an explicit reason.

**Tech Stack:** Rust/Cargo, GitHub Actions, Dependabot, Docker Buildx workflows, `gh`, Git worktrees.

## Global Constraints

- Keep the minimum supported Rust version at exactly 1.88.0.
- Do not modify Panorama discovery or implement Panorama functionality.
- Do not push implementation commits directly to `main`; merge through PRs.
- Preserve the published `v0.2.1` tag and release without retagging.
- Require formatting, Clippy, locked workspace build/tests/docs, fuzz-lock checks, supply-chain policy, and packaging gates before the maintenance PR merges.
- End with zero open Dependabot PRs and a successful final `main` CI run.

---

### Task 1: Merge green policy-compatible PRs

**Files:**
- Modify through existing PRs: `Cargo.lock`
- Modify through existing PRs: `.github/workflows/ci.yml`
- Modify through existing PRs: `.github/workflows/release-image.yml`

**Interfaces:**
- Consumes: successful four-job CI results already attached to PRs #6, #11, #12, #17, #18, #20, and #21.
- Produces: seven dependency-specific squash commits on `main`.

- [x] **Step 1: Reconfirm each PR is open, non-draft, and green**

```bash
for pr in 18 20 21 6 11 12 17; do
  gh pr view "$pr" --json state,isDraft,mergeable,mergeStateStatus,url
  gh pr checks "$pr" --required
done
```

Expected: every PR is open, non-draft, and all required checks pass.

- [x] **Step 2: Merge Cargo patch updates in lockfile order**

```bash
for pr in 18 20 21; do
  gh pr merge "$pr" --squash --delete-branch
done
```

Expected: rcgen 0.14.8, rustls 0.23.41, and reqwest 0.13.4 are on `main`.

- [x] **Step 3: Merge GitHub Actions updates in workflow order**

```bash
for pr in 6 11 12 17; do
  gh pr merge "$pr" --squash --delete-branch
done
```

Expected: checkout v7, login-action v4, setup-buildx-action v4, and metadata-action v6 are on `main`.

- [x] **Step 4: Refresh the maintenance worktree from updated main**

```bash
git fetch origin main
git rebase origin/main
```

Expected: `agent/dependency-maintenance` contains all seven merged updates with no local changes lost.

### Task 2: Repair the SHA-2 and RMCP updates

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `fuzz/Cargo.lock`

**Interfaces:**
- Consumes: `rmcp = { version = "2" }`, `sha2 = "0.10"`, and both existing lockfiles.
- Produces: SHA-2 0.11.0, RMCP 2.2.0, and sse-stream 0.2.4 consistently locked in workspace and fuzz builds.

- [x] **Step 1: Preserve the observed failing evidence**

```text
PR #9 RED: rmcp 2.2.0 selected sse-stream 0.2.3, which lacks
SseStream::from_bytes_stream and fails compilation.
PR #19 RED: workspace tests pass, then fuzz/Cargo.lock is stale and --locked
refuses to update it.
```

- [x] **Step 2: Update the direct SHA-2 requirement**

Change the workspace dependency to:

```toml
sha2 = "0.11"
```

- [x] **Step 3: Update root lockfile packages precisely**

```bash
cargo update -p sha2 --precise 0.11.0
cargo update -p rmcp --precise 2.2.0
cargo update -p sse-stream --precise 0.2.4
```

Expected: root `Cargo.lock` resolves SHA-2 0.11.0, RMCP 2.2.0, and sse-stream 0.2.4.

- [x] **Step 4: Update the fuzz lockfile with the same graph**

```bash
cargo update --manifest-path fuzz/Cargo.toml -p sha2 --precise 0.11.0
```

The fuzz workspace depends on `rust-panosmcp-core`, not the MCP transport
crate, so RMCP and sse-stream are intentionally absent there. Expected:
`cargo check --manifest-path fuzz/Cargo.toml --bins --locked` no longer
requests a lockfile update.

- [x] **Step 5: Verify the resolved versions**

```bash
cargo tree -p rust-panosmcp | rg 'rmcp v2.2.0|sha2 v0.11.0|sse-stream v0.2.4'
cargo tree --manifest-path fuzz/Cargo.toml | rg 'sha2 v0.11.0'
```

Expected: the application graph contains all three exact versions and the
fuzz graph contains SHA-2 0.11.0.

### Task 3: Encode toolchain-update policy

**Files:**
- Modify: `.github/dependabot.yml`

**Interfaces:**
- Consumes: Rust 1.88 MSRV policy and the Docker builder's matching `rust:1.88.0` tag.
- Produces: Dependabot exclusions for policy-controlled Rust toolchain references while retaining other Cargo, Actions, and Docker updates.

- [x] **Step 1: Exclude dtolnay toolchain refs from Actions updates**

Add under the `github-actions` update block:

```yaml
    ignore:
      - dependency-name: dtolnay/rust-toolchain
```

- [x] **Step 2: Exclude the Rust builder from Docker updates**

Add under the `docker` update block:

```yaml
    ignore:
      - dependency-name: rust
```

Expected: Rust compiler/MSRV changes remain deliberate project changes, while all unrelated dependency updates continue normally.

### Task 4: Verify and publish the maintenance PR

**Files:**
- Test: workspace and fuzz lockfiles
- Test: `.github/dependabot.yml`
- Include: `docs/superpowers/plans/2026-07-11-dependency-pr-resolution.md`

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces: one reviewable PR containing only repaired dependencies, lockfiles, policy, and this plan.

- [x] **Step 1: Run local CI-equivalent verification**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace --locked
cargo test --workspace --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked
cargo check --manifest-path fuzz/Cargo.toml --bins --locked
scripts/verify-packaging.sh
```

Expected: all commands exit zero; workspace tests report zero failures.

- [x] **Step 2: Inspect and commit exact scope**

```bash
git diff --check
git status --short
git add Cargo.toml Cargo.lock fuzz/Cargo.lock .github/dependabot.yml \
  docs/superpowers/plans/2026-07-11-dependency-pr-resolution.md
git commit -m "Resolve dependency maintenance queue"
```

Expected: one commit with no unrelated files.

- [ ] **Step 3: Push and open a ready PR**

```bash
git push -u origin agent/dependency-maintenance
gh pr create --base main --head agent/dependency-maintenance \
  --title "Resolve dependency maintenance queue" \
  --body $'## Summary\n\n- update RMCP to 2.2.0 with compatible sse-stream 0.2.4\n- update SHA-2 to 0.11.0 in workspace and fuzz lockfiles\n- stop Dependabot from rewriting policy-controlled Rust toolchain refs\n- keep Panorama deferred\n\n## Validation\n\n- formatting, Clippy, build, tests, docs, fuzz lock, and packaging policy pass\n\nSupersedes #7, #9, #16, and #19.'
```

PR body must explain the repaired #9/#19 failures, policy closure of #7/#16, exact checks, and that Panorama is deferred.

- [ ] **Step 4: Require all PR CI jobs to succeed and merge**

```bash
maintenance_pr=$(gh pr view agent/dependency-maintenance --json number --jq .number)
gh pr checks "$maintenance_pr" --watch --fail-fast
gh pr merge "$maintenance_pr" --squash --delete-branch
```

Expected: maintenance PR is merged into `main` only after all four CI jobs pass.

### Task 5: Close superseded and policy-incompatible PRs

**Files:**
- No repository file changes.

**Interfaces:**
- Consumes: merged maintenance PR and Dependabot policy exclusions.
- Produces: explicit closure records for #7, #9, #16, and #19 if GitHub did not auto-close them.

- [ ] **Step 1: Close nonexistent-toolchain PR #7**

```bash
gh pr close 7 --comment "Closing because Rust 1.100.0 does not exist and the 1.88.0 ref is the project's intentional MSRV policy. Dependabot is now configured not to rewrite policy-controlled toolchain refs."
```

- [ ] **Step 2: Close Docker builder PR #16**

```bash
gh pr close 16 --comment "Closing because the builder remains pinned to the project's Rust 1.88 MSRV. Compiler-version changes will be reviewed as deliberate MSRV updates, and Dependabot is now configured accordingly."
```

- [ ] **Step 3: Close repaired PRs if they remain open**

```bash
gh pr close 9 --comment "Superseded by the merged maintenance PR, which updates rmcp to 2.2.0 together with compatible sse-stream 0.2.4 and validates both lockfiles."
gh pr close 19 --comment "Superseded by the merged maintenance PR, which updates SHA-2 to 0.11.0 and refreshes both the workspace and fuzz lockfiles."
```

Expected: all four are closed or already auto-closed as superseded.

### Task 6: Final main and queue verification

**Files:**
- No repository file changes.

**Interfaces:**
- Consumes: all merged/closed dependency PRs.
- Produces: clean synchronized checkout, zero open PRs, and successful final `main` CI.

- [ ] **Step 1: Refresh and verify main**

```bash
git -C ~/rust-panosmcp fetch origin main
git -C ~/rust-panosmcp pull --ff-only origin main
git -C ~/rust-panosmcp status --short --branch
```

Expected: local `main` equals `origin/main` and is clean.

- [ ] **Step 2: Require zero open PRs**

```bash
test "$(gh pr list --state open --json number --jq length)" -eq 0
```

- [ ] **Step 3: Wait for final main CI**

```bash
run=$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$run" --exit-status
```

Expected: all four final `main` jobs succeed.
