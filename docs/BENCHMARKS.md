# Phase 4 benchmarks

All numbers are environment-specific release-build measurements, not service
level objectives. Re-run them after dependency, compiler, PAN-OS, TLS, or
network changes.

## Repeatable commands

```bash
cargo test --release -p rust-panosmcp-auth \
  --test token_lookup_benchmark -- --ignored --nocapture

cargo test --release -p rust-panosmcp \
  --test mcp_smoke benchmark_in_memory_mcp_read_overhead \
  -- --ignored --nocapture

cargo test --release -p rust-panosmcp-core \
  --test https_client benchmark_warm_pooled_https_read_latency \
  -- --ignored --nocapture
```

The real-firewall comparison uses the same system-info XML command and network
path. Rust includes stdio MCP dispatch, authorization-independent tool
dispatch, XML validation, output caps, strict TLS, and its pooled client. The
Python measurement calls the existing `pan-mcp` tool function directly and
therefore excludes FastMCP dispatch; this deliberately favors Python.

```bash
scripts/benchmark-python-compare.py \
  --rust-binary target/release/rust-panosmcp \
  --rust-inventory /secure/rust-devices.json --rust-device panosvm \
  --python /path/to/pan-mcp/.venv/bin/python \
  --python-project /path/to/pan-mcp \
  --python-inventory /secure/python-devices.json --python-device panosvm \
  --iterations 20 --output /tmp/panosmcp-benchmark.json
```

The script emits only aggregate latency and methodology. It never emits API
keys or endpoints. Run on an idle management plane; alternate implementation
order is built into the harness to reduce drift bias.

## Accepted v0.1 measurements

The accepted host, compiler, sample counts, p50/p95 values, and Python
comparison are recorded in `docs/PHASE4_ACCEPTANCE.md` after the release gate.
