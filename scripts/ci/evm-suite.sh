#!/usr/bin/env bash
# evm-suite.sh <test:fast|test:slow>: run that evm-contracts suite and require the exact mocha passing count pinned
# in lib/test-counts.sh, with nothing pending or failing.
set -euo pipefail
# shellcheck source=scripts/ci/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

suite="${1:?usage: evm-suite.sh <test:fast|test:slow>}"
[ -n "${EVM_PASSING[$suite]:-}" ] || ci_fail "no EVM_PASSING pin for '$suite' in scripts/ci/lib/test-counts.sh"
cd "$REPO_ROOT"
ci_run pnpm --filter evm-contracts run "$suite"
ci_require_success "evm-contracts $suite"
ci_expect_mocha "evm-contracts $suite" "${EVM_PASSING[$suite]}"
echo "evm-contracts $suite: ${EVM_PASSING[$suite]} passing, matches its pin"
