#!/usr/bin/env bash
# Typecheck every TS package that has a typecheck script, except evm-contracts, which the EVM job checks itself.
# Adding a typecheck script without adding the package here leaves it unenforced. The wallets entry covers its
# tests, the only enforcement of the derived-ephemeral brand pin: the package tsconfig excludes test files and
# vitest strips types.
set -euo pipefail
# shellcheck source=scripts/ci/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

cd "$REPO_ROOT"
ci_run pnpm turbo run typecheck \
  --filter=@hisoka/pss-client --filter=@hisoka/pss-server --filter=@hisoka/pss-integration \
  --filter=@hisoka/wallets --filter=@hisoka/prover --filter=@hisoka/howl-e2e \
  --filter=@hisoka/howl-protocol --filter=@hisoka/wallet-runtime --force
ci_require_success "typecheck"
# Eight typecheck tasks plus the builds their ^build dependency pulls in.
ci_expect_turbo_tasks "typecheck" "$TYPECHECK_TASKS"
echo "typecheck: $TYPECHECK_TASKS turbo tasks, matches its pin"
