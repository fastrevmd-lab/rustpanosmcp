# syntax=docker/dockerfile:1.7

# Builder version is taken from rust-toolchain.toml (currently 1.97.0). The two
# must stay in sync. Both image indexes are pinned and Dependabot proposes
# digest refreshes; the explicit Debian generation prevents an unplanned ABI jump.
# Full patch version, deliberately. `rust:1.97-slim-bookworm` is a floating
# tag: it already points at 1.97.1 while rust-toolchain.toml declares 1.97.0,
# so a digest-only Dependabot refresh moves the compiler across a point
# release while the CI sync check still reports a match. Digest resolved from
# the registry 2026-08-24.
FROM rust:1.97.0-slim-bookworm@sha256:6d220bf85c74e842a79da63997af8d2e74455c0b8847d8bb3a5888572334991d AS builder

WORKDIR /src
ENV CARGO_INCREMENTAL=0
ENV RUSTFLAGS="--remap-path-prefix=/src=/usr/src/rust-panosmcp"

COPY Cargo.toml Cargo.lock ./
COPY rust-panosmcp/Cargo.toml rust-panosmcp/Cargo.toml
COPY rust-panosmcp-auth/Cargo.toml rust-panosmcp-auth/Cargo.toml
COPY rust-panosmcp-core/Cargo.toml rust-panosmcp-core/Cargo.toml
COPY rust-panosmcp/src rust-panosmcp/src
COPY rust-panosmcp-auth/src rust-panosmcp-auth/src
COPY rust-panosmcp-core/src rust-panosmcp-core/src

RUN cargo build --release --locked --bin rust-panosmcp

# Runtime base digest verified against registry on 2026-08-24.
# Digests have no version ordering and must be validated by resolving the tag
# against the registry (docker pull gcr.io/distroless/cc-debian13:nonroot),
# never by comparing hashes or by matching sibling repos.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:a77defd6fedbb3392b175ba8ea3d1c22be963c1597c248c3ba987ddd80bfb512

ARG VERSION=0.2.0
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="rust-panosmcp" \
      org.opencontainers.image.description="Secure async MCP server for PAN-OS firewalls" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/fastrevmd-lab/rustpanosmcp" \
      org.opencontainers.image.licenses="MIT"

COPY --from=builder --chown=nonroot:nonroot /src/target/release/rust-panosmcp /usr/local/bin/rust-panosmcp

ENV RUST_LOG=info
EXPOSE 30031
USER 65532:65532
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/rust-panosmcp"]
CMD ["--device-mapping", "/etc/rust-panosmcp/devices.json"]
