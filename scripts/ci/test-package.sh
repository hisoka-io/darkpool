#!/usr/bin/env bash
# test-package.sh <package dir>: run that package's vitest suite and require the exact passed and skipped counts
# pinned in lib/test-counts.sh. pnpm exits 0 when the filter matches nothing or the script is missing, and vitest
# exits 0 with skipped tests, so the exit status alone is not evidence the suite ran.
set -euo pipefail
# shellcheck source=scripts/ci/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

pkg="${1:?usage: test-package.sh <package directory under packages/>}"
[ -n "${VITEST_PASSED[$pkg]:-}" ] || ci_fail "no VITEST_PASSED pin for '$pkg' in scripts/ci/lib/test-counts.sh"
passed="${VITEST_PASSED[$pkg]}"
skipped="${VITEST_SKIPPED[$pkg]:-0}"
name="$(jq -er .name "$REPO_ROOT/packages/$pkg/package.json")" || ci_fail "packages/$pkg/package.json has no name"

cd "$REPO_ROOT"
ci_run pnpm --filter "$name" run test
ci_require_success "$name tests"
ci_expect_vitest "$name" "$passed" "$skipped"
echo "$name: $passed passed, $skipped skipped, matches its pin"
