# Fuzzing

Install `cargo-fuzz`, then run the bounded parser targets:

```bash
cargo fuzz run bearer_header
cargo fuzz run xml_response
cargo fuzz run config_element
cargo fuzz run xpath
cargo fuzz run token_store
```

For a repeatable short release gate, pass
`-- -max_total_time=60 -timeout=5 -rss_limit_mb=1024` to each command. Fuzz
corpora and crash artifacts are intentionally excluded from Git.
