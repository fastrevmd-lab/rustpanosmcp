# v0.2 operator runbook

This runbook covers the Phase 4 systemd and container packages. Read
`PHASE1_OPERATIONS.md`, `PHASE2_OPERATIONS.md`, and `PHASE3_OPERATIONS.md`
before enabling device access, remote HTTP, or mutation respectively.

## Release verification

Release archives contain `BUILD-INFO` and a sibling `.sha256` file. Verify the
checksum before extracting and compare the recorded Git commit with the release
you approved:

```bash
sha256sum --check rust-panosmcp-v0.2.1-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf rust-panosmcp-v0.2.1-x86_64-unknown-linux-gnu.tar.gz
cat rust-panosmcp-v0.2.1/BUILD-INFO
```

The build uses `Cargo.lock`, a fixed Rust MSRV, path remapping, a fixed source
date, deterministic tar ordering/ownership/timestamps, and no incremental
compilation. `scripts/verify-reproducible-build.sh` compiles twice in isolated
target directories and requires byte-identical archives. The container pins
both multi-architecture base-image indexes by digest; treat a digest refresh as
a dependency upgrade requiring CI and image scanning.

## systemd installation

Install the archive and create the static unprivileged account/directories:

```bash
install -o root -g root -m 0755 bin/rust-panosmcp /usr/local/bin/rust-panosmcp
install -o root -g root -m 0644 packaging/systemd/rust-panosmcp.service \
  /etc/systemd/system/rust-panosmcp.service
install -o root -g root -m 0644 packaging/systemd/rust-panosmcp.sysusers \
  /usr/lib/sysusers.d/rust-panosmcp.conf
install -o root -g root -m 0644 packaging/systemd/rust-panosmcp.tmpfiles \
  /usr/lib/tmpfiles.d/rust-panosmcp.conf
systemd-sysusers /usr/lib/sysusers.d/rust-panosmcp.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/rust-panosmcp.conf
```

Install a root-owned inventory that is not group/other writable. API-key files,
TLS private keys, and the token store must be owned by `rust-panosmcp` (or root
when the service can read them) and mode 0600. CA bundles and certificates may
be root-owned 0644.

```bash
install -o root -g rust-panosmcp -m 0640 devices.json \
  /etc/rust-panosmcp/devices.json
install -o rust-panosmcp -g rust-panosmcp -m 0600 panos-api.key \
  /etc/rust-panosmcp/panos-api.key
```

Mint the initial read token as the service account so atomic rotations preserve
ownership. Capture stdout directly into a secret manager:

```bash
sudo -u rust-panosmcp /usr/local/bin/rust-panosmcp \
  -f /etc/rust-panosmcp/devices.json token add \
  --tokens-file /var/lib/rust-panosmcp/tokens.json \
  --name initial-reader --devices panosvm \
  --tools list_devices,gather_device_facts,execute_panos_op,get_panos_config
```

The packaged unit listens only on loopback with bearer authentication and is
intended for a same-host TLS reverse proxy. If native TLS is preferred, create a
systemd drop-in that replaces `ExecStart` with explicit `--tls-cert`,
`--tls-key`, `--allowed-host`, and `--allowed-origin` arguments. Never expose
the packaged loopback/plaintext listener through host networking or a port
forward.

```bash
systemctl daemon-reload
systemctl enable --now rust-panosmcp
systemctl status rust-panosmcp
journalctl -u rust-panosmcp --since today
systemd-analyze security rust-panosmcp.service
```

The unit has no capabilities, a read-only operating-system and configuration
tree, a single writable state directory, private temporary/devices namespaces,
kernel and namespace protections, syscall/address-family restrictions, and
bounded tasks/file descriptors.

### Native TLS renewal for a private-address hostname

When the listener hostname resolves only on private DNS, use ACME DNS-01 rather
than HTTP-01. Keep the DNS provider credential off the application host when
possible. In the lab, certbot and its mode-0600 Cloudflare credential live on
`pve2`; the deploy hook `scripts/deploy-lab-certificate.sh` validates the
chain, hostname, and key pair before using `pct push` to atomically replace the
certificate on LXC 608. A failed service restart restores the previous pair.

Test issuance and deployment separately:

```bash
certbot renew --dry-run
RENEWED_LINEAGE=/etc/letsencrypt/live/rust-panosmcp.mechub.org \
  /etc/letsencrypt/renewal-hooks/deploy/rust-panosmcp-lxc608
curl --fail-with-body https://rust-panosmcp.mechub.org:30031/mcp
```

The unauthenticated MCP request is expected to return HTTP 401 after TLS
verification succeeds. Never use `--insecure` as a health check. Rotate a DNS
API token immediately if its plaintext reaches logs, terminal capture, or an
unapproved secret store.

## Container installation

The final image is distroless: it has no shell or package manager and runs as
UID/GID 65532. The provided Compose example enables native TLS, a read-only root
filesystem, all-capability drop, no-new-privileges, a PID limit, and a small
no-exec tmpfs.

Prepare one bind-mounted `runtime` directory. Inventory and certificates can be
root-owned and read-only. Files classified as secrets must be readable only by
container UID 65532; a typical rootful-host setup uses owner 65532 and mode
0600. Mount the directory, not individual files, so an atomic token-store
replacement is visible in the container.

```bash
docker compose -f packaging/container/compose.example.yaml up -d
docker compose -f packaging/container/compose.example.yaml kill -s SIGHUP rust-panosmcp
```

Do not add a shell to the production image for diagnostics. Use the same image
with higher Rust logging, external network capture under change control, or a
separately identified debug image. Keep the production root filesystem
read-only.

## Zero-downtime bearer-token rotation

Prefer overlapping add/deploy/revoke over in-place rotate:

1. Add `client-next` with the minimum exact scopes and reload using
   `--server-pid` or `systemctl reload rust-panosmcp`.
2. Deliver the one-time plaintext to the client secret manager.
3. Confirm successful calls and audit attribution under `client-next`.
4. Revoke the old token and reload.
5. Confirm the old token returns HTTP 401 and retain only non-secret audit
   evidence.

`token rotate` immediately replaces the previous secret and is appropriate only
when the client and server can change as one transaction. Wildcard tool scope
never grants mutation tools.

## PAN-OS API-key rotation

Use a dedicated, unshared, least-privilege PAN-OS administrator. Generate a new
key under change control, replace the protected key file atomically with owner
and mode preserved, then reload. Run `gather_device_facts` before revoking the
old credential when PAN-OS permits overlap; otherwise schedule the brief
cutover. Inspect PAN-OS administrator logs and rust-panosmcp audit events. A
reload validates files and policy but cannot prove a new key to the firewall
until a request is made.

## Backup and restore

Back up, encrypted and access-controlled:

- the exact release archive/checksum and systemd overrides or container digest;
- inventory, CA bundles/pins, TLS certificate/private key, and digest-only
  bearer-token store;
- PAN-OS API keys in the approved secret manager, separately from inventory;
- durable audit logs and the documented PAN-OS administrator/role definition.

Configure `--state-file /var/lib/rust-panosmcp/mutation-state.json` and include
that private mode-0600 file in the encrypted backup. It contains exact planned
XML payloads as well as operation metadata and must be protected like candidate
configuration. Before backup, upgrade, or disaster recovery, stop new writes
and reconcile every active validation/commit job and configuration lock on
PAN-OS. Restore files with their documented ownership/modes, validate the
checksum, start the same binary/image, perform read-only health calls, inspect
candidate changes and locks, and only then re-enable write tokens.

## Upgrade and rollback

1. Read the release notes/security advisory and verify checksum or image digest.
2. Run the mock gates and the applicable real PAN-OS release-family matrix.
3. Drain mutation clients and reconcile jobs, candidate changes, and config
   locks. Record an encrypted backup.
4. For systemd, stop the service, atomically replace the binary/package assets,
   run `systemctl daemon-reload`, and start. For containers, pull by approved
   digest and recreate without changing read-only mounts/security options.
5. Confirm version, read tools, bearer refusal behavior, audit delivery, and
   PAN-OS candidate/lock state before restoring write traffic.

Rollback uses the previous verified binary/image and matching configuration.
Never roll back by retrying an operation whose commit result is unknown. Follow
the indeterminate-commit procedure in `PHASE3_OPERATIONS.md` first.

## Monitoring and incident recovery

Alert on repeated 401/403/429 responses, reload failures, PAN-OS API errors,
validation/commit failures, indeterminate operations, stale config locks,
unexpected token names, and loss of audit-log delivery. Request and mutation
events intentionally omit credentials and payloads; preserve them in a durable,
access-controlled sink.

For suspected credential exposure, follow `SECURITY.md`. For process loss during
mutation, keep write clients disabled, inspect PAN-OS jobs/change summary/locks,
and reconcile manually before restart or discard. A successful process start is
not proof that the PAN-OS candidate is clean.

If a commit or discard succeeds on PAN-OS but configuration-lock removal
fails, v0.2.1 persists the operation as `indeterminate` with
`config_lock_held: true` and returns an error. Do not retry the mutation. Verify
the job, candidate fingerprint, and live PAN-OS lock, remove the lock if
required, then use the exact offline-resolution confirmation documented in
`PHASE3_OPERATIONS.md`.
