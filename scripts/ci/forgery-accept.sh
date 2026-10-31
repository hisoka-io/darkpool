#!/usr/bin/env bash
# The circuits job runs each harness's reject battery. Only this step proves the un-ablated harness still yields a
# proof native bb verifies, so a reject battery cannot pass by rejecting everything.
set -euo pipefail
# shellcheck source=scripts/ci/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

ci_require_native_bb
cd "$REPO_ROOT"
ci_run env BB_NATIVE_PATH="$CI_BB" bash scripts/run-forgery-harnesses.sh
ci_require_success "forgery harness runner"
[ "$(ci_count '^run-forgery-harnesses: all 3 harnesses PASS \(anti-drift \+ asserted reject battery \+ accept-path\)$')" -eq 1 ] \
  || ci_fail "the forgery harness runner did not reach its all-3-pass assertion"
verified="$(ci_count 'Proof verified successfully')"
[ "$verified" -eq "$FORGERY_VERIFIED_PROOFS" ] \
  || ci_fail "$verified accept paths reported a verified proof, pinned $FORGERY_VERIFIED_PROOFS (one per harness)"
echo "forgery-accept: $verified accept paths verified by native bb, matches its pin"
