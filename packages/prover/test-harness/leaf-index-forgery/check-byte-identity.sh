#!/usr/bin/env bash
# Anti-drift guard: ensures the mirrored hashing body matches lean_imt_inclusion_proof.
#
# Scope: only the body BELOW the path_bits line is mirrored. The index binding itself
# (`leaf_index.to_le_bits()`) is compiler-emitted, not source-level, so it is modelled by a parameter rather
# than mirrored -- see the SSA evidence in src/main.nr.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
REAL="$HERE/../../../circuits/shared/src/lib.nr"
MIRROR="$HERE/src/main.nr"

[ -f "$REAL" ] || { echo "FAIL: real source not found at $REAL"; exit 1; }

norm() { sed -E 's#[[:space:]]//.*$##' | grep -vE '^\s*//' | grep -vE '^\s*$' | sed -E 's#[[:space:]]+# #g; s/^ //; s/ $//'; }

# The real body: from `let mut current = leaf;` to the closing `current`.
real_start=$(grep -n 'let mut current = leaf;' "$REAL" | head -1 | cut -d: -f1)
real_end=$(awk -v s="$real_start" 'NR>s && /^\s*current$/ {print NR; exit}' "$REAL")
[ -n "$real_start" ] && [ -n "$real_end" ] || { echo "FAIL: could not locate lean_imt_inclusion_proof body"; exit 1; }

mir_start=$(grep -n 'let mut current = leaf;' "$MIRROR" | head -1 | cut -d: -f1)
mir_end=$(awk -v s="$mir_start" 'NR>s && /^\s*current$/ {print NR; exit}' "$MIRROR")
[ -n "$mir_start" ] && [ -n "$mir_end" ] || { echo "FAIL: could not locate the mirrored body"; exit 1; }

sed -n "${real_start},${real_end}p" "$REAL" | norm > /tmp/leafidx-real.txt
sed -n "${mir_start},${mir_end}p" "$MIRROR" | norm > /tmp/leafidx-mir.txt

if ! diff -q /tmp/leafidx-real.txt /tmp/leafidx-mir.txt >/dev/null; then
  echo "FAIL: the mirror has DRIFTED from lean_imt_inclusion_proof."
  echo "  real   $REAL:${real_start}-${real_end}"
  echo "  mirror $MIRROR:${mir_start}-${mir_end}"
  echo "  (< real, > mirror)"
  diff /tmp/leafidx-real.txt /tmp/leafidx-mir.txt
  exit 1
fi

# The binding this harness models away must still be present in the real circuit. If a refactor removes the
# 32-bit decomposition, the modelled attack becomes live and this guard must fail loudly.
if ! grep -qE 'let path_bits: \[bool; MAX_DEPTH\] = leaf_index\.to_le_bits\(\);' "$REAL"; then
  echo "FAIL: lean_imt_inclusion_proof no longer binds leaf_index via to_le_bits."
  echo "  the double-spend modelled in this harness may now be LIVE -- see src/main.nr"
  exit 1
fi

echo "OK: mirror matches lean_imt_inclusion_proof (${REAL}:${real_start}-${real_end})"
echo "OK: the real circuit still binds leaf_index via to_le_bits"
echo "    real commit: $(cd "$HERE" && git log -1 --format=%h -- "$REAL" 2>/dev/null)"
exit 0
