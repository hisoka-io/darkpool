#!/usr/bin/env bash
# Anti-drift guard: ensures the mirrored check_binding exactly matches the vendored ScalarField constraint body.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
VENDORED="$HERE/../../../circuits/vendor/noir-edwards/src/scalar_field.nr"
MIRROR="$HERE/src/main.nr"

[ -f "$VENDORED" ] || { echo "FAIL: vendored source not found at $VENDORED"; exit 1; }

norm() { sed -E 's#[[:space:]]//.*$##' | grep -vE '^\s*//' | grep -vE '^\s*$' | sed -E 's#[[:space:]]+# #g; s/^ //; s/ $//'; }

# Extracts the constrained region of `from` from the vendored source.
vend_start=$(grep -n 'if (N < 64) {' "$VENDORED" | head -1 | cut -d: -f1)
vend_end=$(awk -v s="$vend_start" 'NR>s && /assert_max_bit_size::<4>\(\)/ {print NR+1; exit}' "$VENDORED")
[ -n "$vend_start" ] && [ -n "$vend_end" ] || { echo "FAIL: could not locate the vendored constrained region"; exit 1; }

# Extracts the mirrored `check_binding` body.
mir_start=$(grep -n 'fn check_binding<let N: u32>' "$MIRROR" | head -1 | cut -d: -f1)
mir_start=$((mir_start + 1))
mir_end=$(awk -v s="$mir_start" 'NR>s && /assert_max_bit_size::<4>\(\)/ {print NR+1; exit}' "$MIRROR")
[ -n "$mir_end" ] || { echo "FAIL: could not locate check_binding in the mirror"; exit 1; }

sed -n "${vend_start},${vend_end}p" "$VENDORED" \
  | sed -E 's#result\.base4_slices\[i\]#slices[i]#' | norm > /tmp/psicek-vend.txt
sed -n "${mir_start},${mir_end}p" "$MIRROR" | norm > /tmp/psicek-mir.txt

if ! diff -q /tmp/psicek-vend.txt /tmp/psicek-mir.txt >/dev/null; then
  echo "FAIL: the mirror has DRIFTED from the vendored constrained region."
  echo "  vendored $VENDORED:${vend_start}-${vend_end}"
  echo "  mirror   $MIRROR:${mir_start}-${mir_end}"
  echo "  (< vendored, > mirror)"
  diff /tmp/psicek-vend.txt /tmp/psicek-mir.txt
  exit 1
fi

# Verifies the ablated twin differs from check_binding ONLY by the two neutralized binding asserts.
abl_start=$(grep -n 'fn check_binding_ablated<let N: u32>' "$MIRROR" | head -1 | cut -d: -f1)
abl_start=$((abl_start + 1))
abl_end=$(awk -v s="$abl_start" 'NR>s && /assert_max_bit_size::<4>\(\)/ {print NR+1; exit}' "$MIRROR")
[ -n "$abl_end" ] || { echo "FAIL: could not locate check_binding_ablated"; exit 1; }
sed -n "${abl_start},${abl_end}p" "$MIRROR" | norm > /tmp/psicek-abl.txt

EXPECTED_DELTA='< assert(acc - skew as Field == x);
> assert(acc - acc == 0);
< assert(hi * TWO_POW_128 + lo == x);
> assert(x == x);'
ACTUAL_DELTA=$(diff /tmp/psicek-mir.txt /tmp/psicek-abl.txt | grep -E '^[<>]' | sed -E 's/^([<>]) /\1 /')

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

