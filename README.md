# rust-panosmcp

Planning-stage Rust Model Context Protocol server for Palo Alto Networks
PAN-OS firewalls.

The project goal is a small, fast, production-oriented server with the same
security posture as `rust-junosmcp`: bearer-token authentication, per-token
device and tool scopes, TLS, strict remote-bind refusal rules, bounded input
and output, auditable change operations, and efficient connection reuse.

The initial architecture and delivery plan are in [PLAN.md](PLAN.md).

## Status

Planning only. No server code has been implemented yet.

## Project stance

This will be an independent community project and will not claim affiliation
with or endorsement by Palo Alto Networks. Product names and trademarks will
be used only to identify the systems with which the software interoperates.
