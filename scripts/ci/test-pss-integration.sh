#!/usr/bin/env bash
# Through turbo, not pnpm --filter, so `test.dependsOn: ["^build"]` rebuilds what the suite imports through dist;
# a pnpm --filter run would grade whatever bundle happened to be on disk. The task count pins the test plus the
# pss-client, pss-server, wallets, howl-protocol, wallet-runtime and adaptors builds (wallets imports howl-protocol
# and wallet-runtime imports adaptors at runtime).
set -euo pipefail
# shellcheck source=scripts/ci/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

cd "$REPO_ROOT"
ci_run pnpm turbo run test --filter=@hisoka/pss-integration --force
ci_require_success "pss-integration tests"
ci_expect_vitest "@hisoka/pss-integration" "$PSS_INTEGRATION_TESTS" 0
ci_expect_turbo_tasks "pss-integration" "$PSS_INTEGRATION_TASKS"
echo "pss-integration: $PSS_INTEGRATION_TESTS tests in $PSS_INTEGRATION_TASKS turbo tasks, matches its pins"
