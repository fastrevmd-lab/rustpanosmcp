# TODO — post-public-release follow-ups

The repo went public 2026-07-12 (see docs/V0.2.2_ACCEPTANCE.md for the last
release evidence; PLAN.md for architecture). These are the remaining
should-haves from the public-readiness review, none blocking.

## Community surface

- [ ] CODE_OF_CONDUCT.md (Contributor Covenant; rustjunosmcp lacks one too —
      add to both).
- [ ] `.github/ISSUE_TEMPLATE/` (bug + feature) and a PR template.

## Operator experience

- [ ] Operator install script for the release tarball (parity with
      rustjunosmcp's LXC installer): create user/dirs via
      systemd-sysusers/tmpfiles, install binary + unit, print next steps.
      The README currently documents the manual `install`/`systemctl`
      sequence; a script makes it one command.
- [ ] Genericize or relocate `scripts/deploy-lab-certificate.sh` guidance in
      docs/OPERATIONS.md so it reads as a pattern, not a lab artifact.

## Documentation

- [ ] THREAT_MODEL.md: state explicitly that bearer-token timing-attack
      resistance relies on the `subtle` crate's constant-time comparison
      (audit note 2026-07-12: implementation verified, reliance
      undocumented).

## Roadmap (deferred, tracked in PLAN.md)

- [ ] Multi-vsys and HA support — paused until a licensed multi-vsys lab
      resource and second HA peer are available.
- [ ] Panorama — deferred.
- [ ] Consider crates.io publication once the tool surface stabilizes
      (workspace crates would need publishable metadata).
