# syntax=docker/dockerfile:1.7

# Both image indexes are pinned. Dependabot is configured to propose digest
# refreshes; the explicit Debian generation prevents an unplanned ABI jump.
FROM rust:1.88.0-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS builder

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

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:fccdbb0a547c14e23fcf4ce8ad62ca5d43b4faae8d22cd292f490fef9946c96e

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
