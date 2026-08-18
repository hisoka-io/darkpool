#!/usr/bin/env bash
# The OUTCOME of each step is asserted, not just its exit code. Step 3's real proof must VERIFY, which is what
# makes step 2's rejects load-bearing rather than vacuous. CI runs step 3 for frost-forgery only, so this
# runner is the only place all three accept paths are exercised.
set -uo pipefail

# Assertions read their haystack from a here-string, never `echo ... | grep -q`. Under pipefail, `grep -q`
# exits on the first match, `echo` dies of SIGPIPE, and pipefail promotes 141 to the pipeline status -- so a
# PRESENT pattern reported FAILURE roughly one run in three. A mandatory gate that cries wolf gets ignored.

HARNESSES=(frost-forgery psi-cek-forgery leaf-index-forgery)
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HARNESS_ROOT="$REPO_ROOT/packages/prover/test-harness"
BB="${BB_NATIVE_PATH:-$HOME/.bb/bb}"
BB_WANT="5.0.0"

# Minimum passed-test count per harness: a battery that shrinks below this has lost a test.
min_tests_for() {
  case "$1" in
    frost-forgery) echo 8 ;;
    psi-cek-forgery) echo 11 ;;
    leaf-index-forgery) echo 7 ;;
    *) echo 1 ;;
  esac
}

# The reject / differential tests whose presence IS the harness's evidence. Each must actually execute.
required_tests_for() {
  case "$1" in
    frost-forgery)
      echo "forgery_rejected_by_binding_63 forgery_rejected_by_binding_64 forged_witness_passes_every_guard_except_the_binding ablated_rig_still_rejects_a_mutated_z" ;;
    psi-cek-forgery)
      echo "forgery_rejected_by_binding_63 forgery_rejected_by_binding_64 forged_witness_passes_every_guard_except_the_binding ablated_rig_still_rejects_a_mutated_psi" ;;
    leaf-index-forgery)
      echo "unbound_index_yields_two_nullifiers_for_one_leaf modelled_body_still_rejects_a_wrong_sibling modelled_body_still_rejects_a_right_child_at_an_empty_level real_inclusion_proof_rejects_out_of_range_index" ;;
    *) echo "" ;;
  esac
}

[ -x "$BB" ] || {
  echo "FAIL: native bb not executable at $BB (set BB_NATIVE_PATH; install via bbup -v $BB_WANT)."
  echo "      Step 3 (accept-path control) cannot run without it; refusing to report a vacuous pass."
  exit 1
}
# Exact match, not a substring: a bare `grep 5.0.0` would also accept e.g. 15.0.0 or 5.0.0-rc1.
bb_version="$("$BB" --version 2>&1 | tr -d '[:space:]')"
[ "$bb_version" = "$BB_WANT" ] || {
  echo "FAIL: native bb version is '$bb_version', want exactly '$BB_WANT'."
  exit 1
}

failed=0
for h in "${HARNESSES[@]}"; do
  dir="$HARNESS_ROOT/$h"
  echo "==================== $h ===================="
  [ -d "$dir" ] || { echo "FAIL: harness $h missing at $dir"; failed=1; continue; }

  ( cd "$dir" && ./check-byte-identity.sh ) \
    || { echo "FAIL: harness $h step 1 (check-byte-identity) failed"; failed=1; continue; }

  test_out="$(cd "$dir" && nargo test 2>&1)"; test_rc=$?
  echo "$test_out"
  [ "$test_rc" -eq 0 ] \
    || { echo "FAIL: harness $h step 2 (nargo test) failed"; failed=1; continue; }

  passed="$(echo "$test_out" | grep -oE '[0-9]+ tests? passed' | awk '{s+=$1} END {print s+0}')"
  want_min="$(min_tests_for "$h")"
  [ "$passed" -ge "$want_min" ] \
    || { echo "FAIL: harness $h step 2 ran only $passed tests (expected >= $want_min) -- a test was removed or renamed"; failed=1; continue; }
  missing=0
  for tname in $(required_tests_for "$h"); do
    grep -q "Testing $tname" <<< "$test_out" \
      || { echo "FAIL: harness $h step 2 never ran the required test '$tname'"; missing=1; }
  done
  [ "$missing" -eq 0 ] || { failed=1; continue; }

  gold_out="$(cd "$dir" && ./run-gold-standard.sh 2>&1)"; gold_rc=$?
  echo "$gold_out"
  [ "$gold_rc" -eq 0 ] \
    || { echo "FAIL: harness $h step 3 (run-gold-standard) exited $gold_rc"; failed=1; continue; }
  grep -q 'Proof verified successfully' <<< "$gold_out" \
    || { echo "FAIL: harness $h step 3 -- native bb never reported a verified proof (vacuous accept)"; failed=1; continue; }
  grep -q 'VERIFYING proof' <<< "$gold_out" \
    || { echo "FAIL: harness $h step 3 -- did not reach its accept-path success assertion"; failed=1; continue; }

  echo "PASS: $h ($passed tests incl. all required rejects; anti-drift + native-bb accept-path)"
done

if [ "$failed" -ne 0 ]; then
  echo "run-forgery-harnesses: one or more harnesses FAILED"
  exit 1
fi
echo "run-forgery-harnesses: all 3 harnesses PASS (anti-drift + asserted reject battery + accept-path)"
