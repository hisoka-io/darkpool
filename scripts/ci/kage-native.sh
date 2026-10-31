#!/usr/bin/env bash
# The Kage native VK-pin gate must execute: the suite self-skips without native bb or without KAGE_NATIVE=1, and
# vitest reports a skip as success, so both skip notices fail this step and the passed count is exact.
set -euo pipefail
# shellcheck source=scripts/ci/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

ci_require_native_bb
cd "$REPO_ROOT"
ci_run env KAGE_NATIVE=1 BB_NATIVE_PATH="$CI_BB" pnpm --filter @hisoka/prover run test:native
[ "$(ci_count 'skipping \(not passing\)')" -eq 0 ] || ci_fail "Kage native gate SKIPPED: the suite found no usable native bb"
[ "$(ci_count 'opt-in only')" -eq 0 ] || ci_fail "Kage native gate did not receive KAGE_NATIVE=1"
ci_require_success "Kage native gate"
# The tamper battery and the forged-circuit (kage-intent-forger) VK-hash rejection.
ci_expect_vitest "Kage native gate" "$KAGE_NATIVE_TESTS" 0
echo "kage-native: $KAGE_NATIVE_TESTS tests executed against native bb, matches its pin"
