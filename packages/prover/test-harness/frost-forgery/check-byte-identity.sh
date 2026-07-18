#!/usr/bin/env bash
# Anti-drift guard for the mirrored constraint body.
#
# `check_binding` in src/main.nr reproduces the constrained region of `From<Field> for ScalarField<N>::from`
# in packages/circuits/vendor/noir-edwards/src/scalar_field.nr. A mirror that silently desyncs from the real
# `from` proves nothing, so this re-derives the vendored region and compares it to the mirror. Comments and
# blank lines are stripped and whitespace normalised (the mirror carries its own commentary); the CODE must
# match exactly.
#
# Two deviations are applied to the vendored text before comparing, both documented in src/main.nr:
#   1. the final 4-bit loop reads `slices[i]` instead of `result.base4_slices[i]` (identical values; this
#      crate cannot construct a `ScalarField`, whose fields are `pub(crate)` to edwards);
#   2. the hint line is not part of the compared region (it is the injection point, and sits above it).
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
VENDORED="$HERE/../../../circuits/vendor/noir-edwards/src/scalar_field.nr"
MIRROR="$HERE/src/main.nr"

[ -f "$VENDORED" ] || { echo "FAIL: vendored source not found at $VENDORED"; exit 1; }

norm() { sed -E 's#[[:space:]]//.*$##' | grep -vE '^\s*//' | grep -vE '^\s*$' | sed -E 's#[[:space:]]+# #g; s/^ //; s/ $//'; }

# Vendored: the constrained region of `from`, i.e. from the `if (N < 64) {` line through the closing brace of
# the trailing 4-bit loop.
vend_start=$(grep -n 'if (N < 64) {' "$VENDORED" | head -1 | cut -d: -f1)
vend_end=$(awk -v s="$vend_start" 'NR>s && /assert_max_bit_size::<4>\(\)/ {print NR+1; exit}' "$VENDORED")
[ -n "$vend_start" ] && [ -n "$vend_end" ] || { echo "FAIL: could not locate the vendored constrained region"; exit 1; }

# Mirror: the body of `check_binding` (the binding-present variant).
mir_start=$(grep -n 'fn check_binding<let N: u32>' "$MIRROR" | head -1 | cut -d: -f1)
mir_start=$((mir_start + 1))
mir_end=$(awk -v s="$mir_start" 'NR>s && /assert_max_bit_size::<4>\(\)/ {print NR+1; exit}' "$MIRROR")
[ -n "$mir_end" ] || { echo "FAIL: could not locate check_binding in the mirror"; exit 1; }

sed -n "${vend_start},${vend_end}p" "$VENDORED" \
  | sed -E 's#result\.base4_slices\[i\]#slices[i]#' | norm > /tmp/frost-vend.txt
sed -n "${mir_start},${mir_end}p" "$MIRROR" | norm > /tmp/frost-mir.txt

if ! diff -q /tmp/frost-vend.txt /tmp/frost-mir.txt >/dev/null; then
  echo "FAIL: the mirror has DRIFTED from the vendored constrained region."
  echo "  vendored $VENDORED:${vend_start}-${vend_end}"
  echo "  mirror   $MIRROR:${mir_start}-${mir_end}"
  echo "  (< vendored, > mirror)"
  diff /tmp/frost-vend.txt /tmp/frost-mir.txt
  exit 1
fi

# The ablated twin must differ from check_binding by EXACTLY the two binding asserts. Without this, a future
# weakening of a range check inside the twin would make "the forgery is accepted" attributable to something
# other than the binding, with nothing firing.
abl_start=$(grep -n 'fn check_binding_ablated<let N: u32>' "$MIRROR" | head -1 | cut -d: -f1)
abl_start=$((abl_start + 1))
abl_end=$(awk -v s="$abl_start" 'NR>s && /assert_max_bit_size::<4>\(\)/ {print NR+1; exit}' "$MIRROR")
[ -n "$abl_end" ] || { echo "FAIL: could not locate check_binding_ablated"; exit 1; }
sed -n "${abl_start},${abl_end}p" "$MIRROR" | norm > /tmp/frost-abl.txt

EXPECTED_DELTA='< assert(acc - skew as Field == x);
> assert(acc - acc == 0);
< assert(hi * TWO_POW_128 + lo == x);
> assert(x == x);'
ACTUAL_DELTA=$(diff /tmp/frost-mir.txt /tmp/frost-abl.txt | grep -E '^[<>]' | sed -E 's/^([<>]) /\1 /')

if [ "$ACTUAL_DELTA" != "$EXPECTED_DELTA" ]; then
  echo "FAIL: the ablated twin differs from check_binding by more than the two binding asserts."
  echo "  expected delta:"; echo "$EXPECTED_DELTA" | sed 's/^/    /'
  echo "  actual delta:";   echo "$ACTUAL_DELTA"   | sed 's/^/    /'
  exit 1
fi

echo "OK: mirror matches the vendored constrained region (scalar_field.nr:${vend_start}-${vend_end})"
echo "OK: the ablated twin differs by exactly the two binding asserts"
echo "    vendored commit: $(cd "$HERE" && git log -1 --format=%h -- "$VENDORED" 2>/dev/null)"
exit 0

