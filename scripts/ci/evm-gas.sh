#!/usr/bin/env bash
# Gas regression guard: the per-entrypoint ceilings, the KageSettlement breakdown and mature-tree ceilings, and the
# frontier-tree parity and per-insert ceilings. Each bench self-skips without its env flag, so the passing count of
# every file is pinned rather than trusting exit 0. Every bench runs even after one fails, so a regression reports
# all the ceilings it crosses.
set -euo pipefail
# shellcheck source=scripts/ci/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

cd "$REPO_ROOT/packages/evm-contracts"
failed=()
for bench in "${GAS_BENCHES[@]}"; do
  echo "::group::$bench"
  ci_run env GAS_BENCH=1 FRONTIER=1 pnpm exec hardhat test "$bench"
  echo "::endgroup::"
  if ! (ci_require_success "gas bench $bench" && ci_expect_mocha "gas bench $bench" "${GAS_BENCH_PASSING[$bench]}"); then
    failed+=("$bench")
  fi
done
[ "${#failed[@]}" -eq 0 ] || ci_fail "gas guard failed for: ${failed[*]} (each bench's ::error:: line above names the ceiling or count)"
echo "evm-gas: ${#GAS_BENCHES[@]} bench files ran, every passing count matches its pin"
