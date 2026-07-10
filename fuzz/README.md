# Fuzzing

Install `cargo-fuzz`, then run either bounded parser target:

```bash
cargo fuzz run bearer_header
cargo fuzz run xml_response
```

Fuzz corpora and crash artifacts are intentionally excluded from Git.
