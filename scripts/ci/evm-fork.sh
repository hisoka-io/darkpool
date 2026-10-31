#!/usr/bin/env bash
# test/adaptors runs in no other job: hardhat binds it to the test:fork task. A missing secret fails loudly rather
# than skipping, because a skipped job reads as a passing gate.
set -euo pipefail
# shellcheck source=scripts/ci/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

[ -n "${MAINNET_FORK_URL:-}" ] || ci_fail "MAINNET_FORK_URL is not set; the adaptor suite cannot run"
cd "$REPO_ROOT"
ci_run pnpm --filter evm-contracts run test:fork
ci_require_success "adaptor fork suite"
[ "$(ci_count '^[[:space:]]*[0-9]+ passing')" -ge 1 ] || ci_fail "the fork suite reported no passing tests"
