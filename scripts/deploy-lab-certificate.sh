#!/bin/sh
set -eu

VMID="${RUST_PANOSMCP_LAB_VMID:?vmid}"
LINEAGE="${RENEWED_LINEAGE:-/etc/letsencrypt/live/rust-panosmcp.mechub.org}"
CERT_DEST=/etc/rust-panosmcp/server.crt
KEY_DEST=/etc/rust-panosmcp/server.key
STAMP=$(date -u +%Y%m%dT%H%M%SZ)

test -r "$LINEAGE/fullchain.pem"
test -r "$LINEAGE/privkey.pem"

pct exec "$VMID" -- cp -a "$CERT_DEST" "$CERT_DEST.pre-acme-$STAMP"
pct exec "$VMID" -- cp -a "$KEY_DEST" "$KEY_DEST.pre-acme-$STAMP"
pct push "$VMID" "$LINEAGE/fullchain.pem" "$CERT_DEST.new" \
    --user root --group root --perms 0644
pct push "$VMID" "$LINEAGE/privkey.pem" "$KEY_DEST.new" \
    --user rust-panosmcp --group rust-panosmcp --perms 0600

pct exec "$VMID" -- openssl verify -untrusted "$CERT_DEST.new" "$CERT_DEST.new"
pct exec "$VMID" -- openssl x509 -in "$CERT_DEST.new" \
    -checkhost rust-panosmcp.mechub.org -noout

CERT_KEY=$(
    pct exec "$VMID" -- sh -c \
        "openssl x509 -in '$CERT_DEST.new' -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum" \
        | awk '{print $1}'
)
PRIVATE_KEY=$(
    pct exec "$VMID" -- sh -c \
        "openssl pkey -in '$KEY_DEST.new' -pubout -outform DER | sha256sum" \
        | awk '{print $1}'
)
test "$CERT_KEY" = "$PRIVATE_KEY"

pct exec "$VMID" -- mv -f "$CERT_DEST.new" "$CERT_DEST"
pct exec "$VMID" -- mv -f "$KEY_DEST.new" "$KEY_DEST"

if ! pct exec "$VMID" -- systemctl restart rust-panosmcp; then
    pct exec "$VMID" -- cp -a "$CERT_DEST.pre-acme-$STAMP" "$CERT_DEST"
    pct exec "$VMID" -- cp -a "$KEY_DEST.pre-acme-$STAMP" "$KEY_DEST"
    pct exec "$VMID" -- systemctl restart rust-panosmcp
    exit 1
fi

pct exec "$VMID" -- systemctl is-active rust-panosmcp
