# Contributing

The project is in staged development. Phase 0 intentionally exposes no PAN-OS
tools and opens no HTTP listener.

## Local checks

Run the same core checks as CI:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --locked
cargo doc --workspace --no-deps --locked
cargo audit --deny warnings
cargo deny check licenses bans sources
```

Fuzz targets live in the isolated `fuzz` workspace:

```bash
cargo fuzz run bearer_header
cargo fuzz run xml_response
```

Do not commit device inventory, bearer tokens, PAN-OS API keys, private keys,
certificate bundles, packet captures, or configuration exports. Real-device
tests must remain opt-in and must target a disposable lab.
