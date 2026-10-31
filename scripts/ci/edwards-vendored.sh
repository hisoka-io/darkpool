#!/usr/bin/env bash
# The vendored noir-edwards library tests. nargo refuses a package that is not a workspace member ("Selected package
# `edwards` was not found"), so this tests a copy outside the workspace. circuit-guards.sh pins the vendored bytes to
# VENDOR-HASHES.sha256, so the copy is the reviewed source and its count moves only with a reviewed re-vendor.
set -euo pipefail
# shellcheck source=scripts/ci/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

cp -r "$REPO_ROOT/packages/circuits/vendor/noir-edwards" "$CI_TMP/noir-edwards"
ci_run nargo test --program-dir "$CI_TMP/noir-edwards"
ci_require_success "vendored noir-edwards tests"
ran="$(ci_nargo_passed)"
[ "$ran" = "edwards $EDWARDS_TESTS" ] \
  || ci_fail "vendored noir-edwards reported '${ran:-no passed line}', pinned 'edwards $EDWARDS_TESTS'; a re-vendor must update EDWARDS_TESTS in scripts/ci/lib/test-counts.sh."
echo "edwards: $EDWARDS_TESTS tests, matches its pin"
