#!/usr/bin/env bash
# Each soundness harness is its own nargo project outside the circuits workspace, so the workspace formatting step
# never reaches it.
set -euo pipefail
# shellcheck source=scripts/ci/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

shopt -s nullglob
n=0
for toml in "$REPO_ROOT"/packages/prover/test-harness/*/Nargo.toml; do
  h="$(dirname "$toml")"
  (cd "$h" && nargo fmt --check) || ci_fail "${h#"$REPO_ROOT"/} is not nargo-fmt clean; run nargo fmt there"
  n=$((n + 1))
done
[ "$n" -gt 0 ] || ci_fail "no soundness harness crate found under packages/prover/test-harness"
echo "harness-fmt: $n harness crates are nargo-fmt clean"
