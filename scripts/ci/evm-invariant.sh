#!/usr/bin/env bash
# Foundry invariant fuzzing of the money paths. forge's summary counts are pinned so a removed or skipped invariant
# fails the step.
set -euo pipefail
# shellcheck source=scripts/ci/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

cd "$REPO_ROOT"
ci_run pnpm --filter evm-contracts run test:invariant
ci_require_success "forge invariant tests"
n="$FORGE_INVARIANT_TESTS"
[ "$(ci_count ": ${n} tests passed, 0 failed, 0 skipped \(${n} total tests\)")" -eq 1 ] \
  || ci_fail "forge reported '$(grep -E 'tests passed, [0-9]+ failed' "$CI_LOG" || echo 'no summary')', pinned ${n} passed, 0 failed, 0 skipped; update FORGE_INVARIANT_TESTS in scripts/ci/lib/test-counts.sh in the same reviewed change."
echo "evm-invariant: $n invariant tests, matches its pin"
