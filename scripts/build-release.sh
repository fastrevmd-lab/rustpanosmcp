#!/usr/bin/env bash
# Build a deterministic release archive and SHA-256 checksum.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ "${PANOSMCP_ALLOW_DIRTY:-0}" != "1" ]] \
    && [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    echo "refusing a release archive from a dirty worktree" >&2
    exit 1
fi

VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)"
if [[ -z "$VERSION" ]]; then
    echo "workspace version not found" >&2
    exit 1
fi
COMMIT="$(git rev-parse --verify HEAD)"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"
TARGET_TRIPLE="${PANOSMCP_TARGET_TRIPLE:-$(rustc -vV | sed -n 's/^host: //p')}"
TARGET_DIR="${PANOSMCP_TARGET_DIR:-$ROOT/target}"
OUTPUT_DIR="${PANOSMCP_OUTPUT_DIR:-$ROOT/dist}"
ARCHIVE="rust-panosmcp-v${VERSION}-${TARGET_TRIPLE}.tar.gz"
BUILD_ARGS=(--release --locked --bin rust-panosmcp)
if [[ "${PANOSMCP_OFFLINE:-0}" == "1" ]]; then
    BUILD_ARGS+=(--offline)
fi

export SOURCE_DATE_EPOCH CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$TARGET_DIR"
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--remap-path-prefix=$ROOT=/usr/src/rust-panosmcp"
cargo build "${BUILD_ARGS[@]}"

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT
PKG="$STAGING/rust-panosmcp-v${VERSION}"
install -d "$PKG/bin" "$PKG/packaging/systemd" "$PKG/docs"
install -m 0755 "$TARGET_DIR/release/rust-panosmcp" "$PKG/bin/rust-panosmcp"
install -m 0644 LICENSE-APACHE LICENSE-MIT README.md SECURITY.md "$PKG/"
install -m 0644 docs/OPERATIONS.md docs/COMPATIBILITY.md docs/BENCHMARKS.md \
    docs/V0.2_CHANGE_SETS.md "$PKG/docs/"
install -m 0644 packaging/systemd/rust-panosmcp.service \
    packaging/systemd/rust-panosmcp.sysusers \
    packaging/systemd/rust-panosmcp.tmpfiles "$PKG/packaging/systemd/"
{
    printf 'version=%s\n' "$VERSION"
    printf 'git_commit=%s\n' "$COMMIT"
    printf 'source_date_epoch=%s\n' "$SOURCE_DATE_EPOCH"
    printf 'target=%s\n' "$TARGET_TRIPLE"
    rustc -vV
} >"$PKG/BUILD-INFO"

mkdir -p "$OUTPUT_DIR"
tar --sort=name --format=ustar --owner=0 --group=0 --numeric-owner \
    --mtime="@$SOURCE_DATE_EPOCH" -C "$STAGING" -cf - "$(basename "$PKG")" \
    | gzip -n -9 >"$OUTPUT_DIR/$ARCHIVE"
(
    cd "$OUTPUT_DIR"
    sha256sum "$ARCHIVE" >"$ARCHIVE.sha256"
)
echo "$OUTPUT_DIR/$ARCHIVE"
