#!/usr/bin/env bash
# Live end-to-end witness round-trip per docs/success-criteria.md §M-E2E.
#
# This wrapper exists for one reason: the test client mnemonic lives in the
# gnome-keyring (per the project's credential-governance rule) and must
# never touch a file or argv. The wrapper looks it up once via
# `secret-tool`, exports it as an env var for the duration of the cargo
# run, and unsets it on exit.
#
# Usage:
#   tests/e2e/live_roundtrip.sh                # default base_url
#   BASE_URL=https://other.host ./live_roundtrip.sh
#
# Exit codes:
#   0  full e2e success
#   1  precondition failure (missing keyring entry, missing tools, etc)
#   *  any failed step inside the binary

set -euo pipefail
umask 077

base_url="${BASE_URL:-https://timestamp.inblock.io}"

# Resolve the repo root so the script works no matter where it is invoked
# from (CI, a different worktree, etc).
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"

# Precondition: keyring entry must exist.
mnemonic="$(secret-tool lookup service aqua-timestamp-test-client user clawi kind mnemonic || true)"
if [[ -z "${mnemonic}" ]]; then
  echo "fatal: keyring entry missing under service=aqua-timestamp-test-client user=clawi kind=mnemonic" >&2
  echo "       seed it once with: secret-tool store --label='Aqua Timestamp test client' service aqua-timestamp-test-client user clawi kind mnemonic" >&2
  exit 1
fi

# Probe the deployment is alive before we do anything else; a 200 here
# proves DNS + TLS + reverse proxy + container are all serving. If this
# fails we exit immediately so the failure message points at the
# infrastructure, not the test code.
echo "probing ${base_url}/health ..."
http_status="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "${base_url}/health")"
if [[ "${http_status}" != "200" ]]; then
  echo "fatal: GET ${base_url}/health returned HTTP ${http_status}" >&2
  exit 1
fi
echo "OK   /health = 200"
echo

# Export the mnemonic for the child process only.
export AQUA_TIMESTAMP_TEST_CLIENT_MNEMONIC="${mnemonic}"
trap 'unset AQUA_TIMESTAMP_TEST_CLIENT_MNEMONIC' EXIT
unset mnemonic

# Run the live subcommand. The binary is built in --release for two
# reasons:
#   1. SDK signature paths use heavier crypto primitives that benefit
#      noticeably from `opt-level = 3` here (a debug-build roundtrip
#      occasionally bumps into reqwest connect-timeout headroom).
#   2. The binary doubles as a release artefact: a `cargo install` from
#      this crate is the easy way to ship the test client to other dev
#      machines.
cd "${repo_root}"
exec cargo run --release --quiet --bin aqua-timestamp-e2e -- live \
  --base-url "${base_url}"
