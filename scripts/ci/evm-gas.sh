#!/usr/bin/env bash
# Gas regression guard: the per-entrypoint ceilings, the KageSettlement breakdown and mature-tree ceilings, and the
# frontier-tree parity and per-insert ceilings. Each bench self-skips without its env flag, so the passing count of
# every file is pinned rather than trusting exit 0.
set -euo pipefail
# shellcheck source=scripts/ci/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

cd "$REPO_ROOT/packages/evm-contracts"
for bench in "${GAS_BENCHES[@]}"; do
  echo "::group::$bench"
  ci_run env GAS_BENCH=1 FRONTIER=1 pnpm exec hardhat test "$bench"
  ci_require_success "gas bench $bench"
  ci_expect_mocha "gas bench $bench" "${GAS_BENCH_PASSING[$bench]}"
  echo "::endgroup::"
done
echo "evm-gas: ${#GAS_BENCHES[@]} bench files ran, every passing count matches its pin"
