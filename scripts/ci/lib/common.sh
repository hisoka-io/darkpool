# shellcheck shell=bash
# Sourced by every scripts/ci step script. Those scripts are the whole body of their ci.yml step and run unchanged
# in a local CI mirror, so nothing here may depend on GitHub-only state.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=scripts/ci/lib/test-counts.sh
source "$REPO_ROOT/scripts/ci/lib/test-counts.sh"

# Every count assertion below reads literal spaces, so colour codes must not sit between a label and its number.
export NO_COLOR=1
unset FORCE_COLOR

# GitHub renders "::error::" as an annotation; elsewhere it is a plain line.
ci_fail() {
  echo "::error::$*"
  exit 1
}

CI_TMP="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/hisoka-ci.XXXXXX")"
trap 'rm -rf "$CI_TMP"' EXIT
CI_LOG="$CI_TMP/output.log"
CI_RC=0

# ci_run <command...>: stream the command's output and keep a copy, colour codes and carriage returns removed, in
# $CI_LOG for the assertions. The exit status lands in CI_RC; the caller decides what a non-zero status means.
ci_run() {
  set +e
  "$@" 2>&1 | tee "$CI_TMP/output.raw"
  CI_RC=${PIPESTATUS[0]}
  set -e
  sed -E $'s/\x1b\\[[0-9;?]*[A-Za-z]//g; s/\r$//' "$CI_TMP/output.raw" > "$CI_LOG"
}

ci_require_success() {
  [ "$CI_RC" -eq 0 ] || ci_fail "$1 exited $CI_RC"
}

# ci_count <ERE>: number of lines of $CI_LOG that match.
ci_count() {
  grep -cE "$1" "$CI_LOG" || true
}

# ci_expect_vitest <label> <passed> <skipped>: vitest's single "Tests" summary line must equal the pin exactly,
# so a skipped, todo or missing test fails the step even though vitest exits 0 for it.
ci_expect_vitest() {
  local label=$1 passed=$2 skipped=$3 want summaries
  if [ "$skipped" -eq 0 ]; then
    want="Tests +${passed} passed \(${passed}\)"
  else
    want="Tests +${passed} passed \| ${skipped} skipped \($((passed + skipped))\)"
  fi
  summaries="$(grep -E '(^|[[:space:]])Tests +[0-9]+ ' "$CI_LOG" || true)"
  [ -n "$summaries" ] || ci_fail "$label printed no vitest 'Tests' summary; the suite did not run"
  [ "$(grep -c . <<< "$summaries")" -eq 1 ] || ci_fail "$label printed more than one vitest 'Tests' summary: $(tr -s ' \n' ' ' <<< "$summaries")"
  grep -qE "(^|[[:space:]])${want}[[:space:]]*$" <<< "$summaries" \
    || ci_fail "$label reported '$(sed -E 's/^.*(Tests +)/\1/' <<< "$summaries")', pinned ${passed} passed and ${skipped} skipped. A test was added, removed or skipped; update scripts/ci/lib/test-counts.sh in the same reviewed change."
}

# ci_expect_mocha <label> <passing>: exactly one mocha "N passing" epilogue equal to the pin, and no pending or
# failing line, so a skipped or deleted test fails the step.
ci_expect_mocha() {
  local label=$1 passing=$2 lines
  lines="$(grep -E '^[[:space:]]*[0-9]+ passing' "$CI_LOG" || true)"
  [ -n "$lines" ] || ci_fail "$label printed no mocha 'passing' summary; the suite did not complete"
  [ "$(grep -c . <<< "$lines")" -eq 1 ] || ci_fail "$label printed more than one mocha summary: $(tr -s ' \n' ' ' <<< "$lines")"
  grep -qE "^[[:space:]]*${passing} passing( \([^)]*\))?[[:space:]]*$" <<< "$lines" \
    || ci_fail "$label reported '$(sed -E 's/^[[:space:]]*//' <<< "$lines")', pinned ${passing} passing. A test was added or removed; update scripts/ci/lib/test-counts.sh in the same reviewed change."
  [ "$(ci_count '^[[:space:]]*[0-9]+ pending')" -eq 0 ] \
    || ci_fail "$label has pending (skipped) tests: $(grep -E '^[[:space:]]*[0-9]+ pending' "$CI_LOG" | tr -s ' ')"
  [ "$(ci_count '^[[:space:]]*[0-9]+ failing')" -eq 0 ] \
    || ci_fail "$label has failing tests: $(grep -E '^[[:space:]]*[0-9]+ failing' "$CI_LOG" | tr -s ' ')"
}

# ci_expect_turbo_tasks <label> <n>: turbo exits 0 when a filter matches nothing or a package lacks the task, so the
# task count is the evidence that every package ran.
ci_expect_turbo_tasks() {
  local label=$1 n=$2
  [ "$(ci_count "Tasks: +${n} successful, ${n} total")" -eq 1 ] \
    || ci_fail "$label ran '$(grep -E 'Tasks: +[0-9]+' "$CI_LOG" | tr -s ' ' || echo 'no turbo summary')', pinned ${n} successful of ${n}; a filter, a package script or a build dependency is missing."
}

# ci_nargo_passed: "<crate> <passed>" for every "[crate] N tests passed" line in $CI_LOG.
ci_nargo_passed() {
  sed -nE 's/^\[([^]]+)\] ([0-9]+) tests? passed$/\1 \2/p' "$CI_LOG"
}

# ci_require_native_bb: the native bb must exist and equal BB_VERSION in generate_verifier.js, the single source the
# verifier generator and check-vk-identity.sh read. Sets CI_BB to its path.
ci_require_native_bb() {
  local want got
  CI_BB="${BB_NATIVE_PATH:-$HOME/.bb/bb}"
  want="$(sed -nE 's/^const BB_VERSION = "([^"]+)";.*/\1/p' "$REPO_ROOT/packages/prover/scripts/generate_verifier.js")"
  [ -n "$want" ] || ci_fail "could not read BB_VERSION from packages/prover/scripts/generate_verifier.js"
  [ -x "$CI_BB" ] || ci_fail "native bb not installed at $CI_BB (install bb $want with .github/actions/setup-bb, or set BB_NATIVE_PATH)"
  got="$("$CI_BB" --version 2>&1 | tr -d '[:space:]')"
  [ "$got" = "$want" ] || ci_fail "native bb at $CI_BB is '$got', want exactly '$want'"
}
