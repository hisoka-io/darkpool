#!/usr/bin/env bash
# nargo test over the circuits workspace. nargo has no skip, so a lost test shows only as a lower count: every
# crate's passed count is pinned in lib/test-counts.sh, and a crate that appears or disappears also fails.
set -euo pipefail
# shellcheck source=scripts/ci/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

cd "$REPO_ROOT/packages/circuits"
ci_run nargo test
ci_require_success "nargo test (packages/circuits)"

ran="$(ci_nargo_passed | LC_ALL=C sort)"
pinned="$(for crate in "${!NARGO_CRATE_TESTS[@]}"; do echo "$crate ${NARGO_CRATE_TESTS[$crate]}"; done | LC_ALL=C sort)"
if [ "$ran" != "$pinned" ]; then
  diff <(echo "$pinned") <(echo "$ran") | sed -nE 's/^</  pinned:/p; s/^>/  ran:   /p' || true
  ci_fail "nargo test per-crate counts differ from NARGO_CRATE_TESTS in scripts/ci/lib/test-counts.sh (see the lines above); a test or crate was added, removed or renamed, so update the pin in the same reviewed change."
fi
total="$(awk '{s += $2} END {print s + 0}' <<< "$ran")"
echo "circuits: ${#NARGO_CRATE_TESTS[@]} crates, $total tests, every crate matches its pin"
