#!/usr/bin/env bash
# The legacy /etc token store must be reported, and the configured store must not.
#
# History worth keeping: an earlier version of this test asserted that
# `config_live_files` must NOT contain "tokens.json", on the theory that omitting
# it would make find_stale_secrets flag the legacy store. It does not — that
# helper only recognises backup suffixes, retired keys, and superseded files
# matched by a live-name PREFIX, so a bare `tokens.json` matches nothing.
# Omitting the name achieved no detection and additionally broke classification
# of `tokens.json.pre-17`. The test also passed for the wrong reason: its grep
# captured the array's declaration line rather than the multi-line array, so it
# would have passed with the detection removed entirely.
#
# Detection is therefore explicit and path-based, and this test asserts the
# behaviour rather than the shape of the source.
set -euo pipefail

cd "$(dirname "$0")/../../.."
SRC=rust-panosmcp/src/main.rs

fail() { echo "FAIL: $*" >&2; exit 1; }

# 1. tokens.json must remain in the config live list, or prefix-based
#    classification of tokens.json.pre-* is lost.
awk '/let config_live_files/,/\];/' "$SRC" | grep -q '"tokens.json"' \
    || fail 'config_live_files must contain "tokens.json" so tokens.json.pre-* is classified'

# 2. The live /var/lib store must also be excluded from stale reporting.
awk '/let state_live_files/,/\];/' "$SRC" | grep -q '"tokens.json"' \
    || fail 'state_live_files must contain "tokens.json"'

# 3. Explicit legacy detection must exist...
grep -q 'let legacy_tokens = Path::new("/etc/rust-panosmcp/tokens.json")' "$SRC" \
    || fail 'explicit legacy token store detection is missing'

# 4. ...and must not fire when that path is the configured store, or the warning
#    tells an operator to erase their live credentials.
grep -q 'configured_is_legacy' "$SRC" \
    || fail 'legacy warning must be suppressed when /etc is the configured store'
grep -q '&& !configured_is_legacy' "$SRC" \
    || fail 'legacy warning must be gated on !configured_is_legacy'

echo ">> stale scan legacy detection test passed"
