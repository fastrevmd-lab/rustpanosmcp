# Contributing to rustpanosmcp

Thanks for considering a contribution. rustpanosmcp is an async Rust Model
Context Protocol server for Palo Alto Networks PAN-OS firewalls — part of the
[mechub](https://github.com/fastrevmd-lab) family of open-source, self-hosted
network-security automation tooling. See [README.md](README.md) for what the
server does, [PLAN.md](PLAN.md) for the architecture and delivery plan, and
[THREAT_MODEL.md](THREAT_MODEL.md) for the security boundaries and
release-blocking controls.

## Before you start

- Check open issues and PRs first — someone may already be working on it.
- For anything larger than a small fix, open an issue to discuss the approach
  before writing code. It saves everyone a rewrite.
- This project follows one hard rule across the whole mechub fleet:
  **deterministic code decides, a model may explain, a human approves.**
  Nothing you contribute should let an LLM or other model output directly
  drive a device action (a candidate `set`/`delete`, a `commit`, a change-set
  approval). Models may draft, summarize, or explain; deterministic code
  decides, and change-set approval always requires a distinct, authenticated
  principal — self-approval is refused in code, not by convention.

## Workspace layout

This is a Cargo workspace with three members, plus an isolated `fuzz`
workspace that is intentionally excluded from it:

- `rust-panosmcp/` — the MCP binary and stdio/streamable-HTTP transport adapter
- `rust-panosmcp-auth/` — bearer-token secret-handling foundations
- `rust-panosmcp-core/` — inventory, PAN-OS client, validation, and tool logic
- `fuzz/` — isolated `cargo-fuzz` workspace (parser and header fuzz targets)
- `config/`, `docs/`, `packaging/`, `scripts/` — configuration examples,
  operator documentation, container/systemd assets, and release/verification
  scripts

## Build and test

Matching what CI runs (`.github/workflows/ci.yml`, `build-test` job):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace --locked
cargo test --workspace --locked
cargo doc --workspace --no-deps --locked
cargo check --manifest-path fuzz/Cargo.toml --bins --locked
```

CI also runs an MSRV check pinned to the `rust-version` in the workspace
`Cargo.toml` (kept in sync with `rust-toolchain.toml`) and a package
conformance job that builds the release binary and container image. You don't
need to reproduce those locally for a normal contribution.

Dependency, license, and supply-chain checks, also required to pass in CI
(`ci.yml`'s `supply-chain` job and `.github/workflows/security.yml`):

```bash
cargo install cargo-audit --locked
cargo install cargo-deny --locked
cargo audit --deny warnings
cargo audit --file fuzz/Cargo.lock --no-fetch --deny warnings
cargo deny check licenses bans sources
cargo deny --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml check licenses bans sources
```

`.github/workflows/security.yml` additionally runs `gitleaks` secret scanning
on every push and pull request.

### Fuzz targets

Fuzz targets live in the isolated `fuzz` workspace. CI only compiles them;
running them is opt-in and not required for a normal contribution:

```bash
cargo fuzz run bearer_header
cargo fuzz run xml_response
```

### Packaging and release verification

If you touch the `Dockerfile`, `packaging/`, or release scripting, also run:

```bash
scripts/verify-packaging.sh
scripts/verify-reproducible-build.sh
```

## Commit and PR conventions

- Match the existing commit style: `type(scope): summary` (`fix(cli):`,
  `chore(deps):`, `build(deps):`, etc.) — see the commit history for examples.
- Keep PRs focused on one change. A bug fix doesn't need a drive-by refactor
  riding along.
- Fill out the PR template, including the exact commands you ran to verify
  the change.
- By opening a pull request, you're agreeing your contribution is licensed
  under this repository's [MIT license](LICENSE).
- All contributions land as a pull request against `main` for human review —
  there is no direct-push path to `main`.

## Review process

Every pull request goes through a security review and a code review, then an
independent test run, before anything merges. Only a maintainer merges —
contributors, including anyone with write access, should not merge their own
PR. CI (build, test, clippy, fmt, MSRV, `cargo audit`, `cargo deny`,
`gitleaks`, packaging conformance) must be green first.

## Reporting a vulnerability

Please don't open a public issue for a security vulnerability — see
[SECURITY.md](SECURITY.md) for how to report one privately.

## Fixtures and test data

Never commit real device inventory, hostnames, serial numbers, bearer
tokens, PAN-OS API keys, private keys, certificate bundles, packet captures,
or configuration exports — synthetic or sanitized fixtures only (see the
`config/*.example.json` files for the pattern to follow). Real-device tests
must remain opt-in and target only a disposable lab. If you find real data
already committed anywhere in this repo, don't add to it — report it
privately instead (see [SECURITY.md](SECURITY.md)).
