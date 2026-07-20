#!/usr/bin/env bash
# Circuit regression guards: fails CI if fragile cryptographic constructs are introduced.
set -u

CIRCUITS_DIR="${CIRCUITS_DIR:-packages/circuits}"
CIRCUITS_ABS="$(realpath -m "$CIRCUITS_DIR")"
BASELINE_MUL_SITES=39          # guard 4: .mul( / derive_* / assert_subgroup_scalar / check_subgroup surface
BASELINE_POS_SITES=25          # guard 5: Poseidon2::hash( call surface
BASELINE_SCALARFIELD_SITES=2   # guard 9: ScalarField occurrences (alias / generic-propagation tripwire)

fail=0
red() { echo "FAIL (guard $1): $2"; fail=1; }

# Scans all .nr files except top-level vendor/ and target/ dirs.
src_grep() { grep -rnE "$1" "$CIRCUITS_DIR" --include='*.nr' | grep -vE "^${CIRCUITS_DIR}/(vendor|target)/"; }
# Strips lines starting with // from grep output.
decomment() { grep -vE '^[^:]*:[0-9]+:[[:space:]]*//'; }

# Guard 0: Forbids remote git dependencies in Nargo.toml to prevent supply chain attacks (requires local vendoring).
if grep -rnE '(^|[^A-Za-z_])("|'"'"')?(git|tag|rev|branch|directory)("|'"'"')?[[:space:]]*=' "$CIRCUITS_DIR" --include=Nargo.toml; then
  red 0 "a circuit Nargo.toml uses a git dependency; vendor it under packages/circuits/vendor/."
fi
# Deep layer (Guards 0/8): Python TOML parse to guarantee path dependencies resolve strictly inside packages/circuits.
if command -v python3 >/dev/null 2>&1 && python3 -c 'import tomllib' >/dev/null 2>&1; then
  if ! python3 - "$CIRCUITS_DIR" <<'PY'
import sys, os, glob, tomllib
root = sys.argv[1]
root_abs = os.path.realpath(root)
bad = []
for toml in glob.glob(os.path.join(root, '**', 'Nargo.toml'), recursive=True):
    if os.sep + 'target' + os.sep in toml:
        continue
    try:
        with open(toml, 'rb') as fh:
            data = tomllib.load(fh)
    except Exception as e:
        bad.append(f"{toml}: unparseable TOML ({e})"); continue
    for spec_name, spec in (data.get('dependencies', {}) or {}).items():
        if not isinstance(spec, dict):
            bad.append(f"{toml}: dependency '{spec_name}' is not a path table"); continue
        keys = set(spec.keys())
        if keys != {'path'}:
            bad.append(f"{toml}: dependency '{spec_name}' must be a pure path dep (keys={sorted(keys)})"); continue
        tgt = os.path.realpath(os.path.join(os.path.dirname(toml), spec['path']))
        if os.path.commonpath([tgt, root_abs]) != root_abs:
            bad.append(f"{toml}: dependency '{spec_name}' path escapes packages/circuits -> {spec['path']}")
for b in bad:
    print("  guard0/8-deep:", b)
sys.exit(1 if bad else 0)
PY
  then red 0 "dependency allowlist rejected a circuit Nargo.toml (non-path source or escaping path)."; fi
  DEEP_TOML=ok
else
  DEEP_TOML=skipped
  echo "NOTE: python3+tomllib unavailable; guards 0/8 deep TOML parse skipped (grep + realpath layers still ran)."
fi

# Guard 1: Forbids ScalarField<64> to prevent negative representative wraparound bugs; forces <63>.
if src_grep 'ScalarField[[:space:]]*(::)?[[:space:]]*<[[:space:]]*64[[:space:]]*>' | decomment | grep .; then
  red 1 "ScalarField<64> in circuit code (accepts a negative representative); use <63>, or a fixed edwards build."
fi

# Guard 2: Forbids msm() calls as they lack on-curve checks; forces mul().
if src_grep '(^|[^A-Za-z0-9_])msm[[:space:]]*(::[^(]*)?\(' | decomment | grep .; then
  red 2 "msm() call site; use mul(), or add an on-curve check before use."
fi

# Guard 3: Forbids Poseidon2 streaming API to prevent array/streaming length divergence; forces Poseidon2::hash.
if src_grep 'Poseidon2Hasher|std::hash::Hasher|perform_duplex|\.absorb[[:space:]]*\(|\.squeeze[[:space:]]*\(|derive\(Hash\)' \
     | decomment | grep .; then
  red 3 "Poseidon2 streaming/Hasher API (can diverge from the array API); use Poseidon2::hash."
fi

# Guard 4: Pins scalar multiplication count. Deviations force manual review of bounds checking.
MUL=$(src_grep '\.mul[[:space:]]*\(|derive_public_key|derive_shared_key|assert_subgroup_scalar|check_subgroup' | wc -l | tr -d ' ')
if [ "$MUL" -ne "$BASELINE_MUL_SITES" ]; then
  red 4 "scalar-mul/subgroup-gate surface changed ($MUL vs baseline $BASELINE_MUL_SITES); confirm every non-BASE8 mul/derive is dominated by assert_subgroup_scalar/check_subgroup, then re-baseline."
fi

# Guard 5: Pins Poseidon2::hash count. Deviations force manual review of array lengths.
POS=$(src_grep 'Poseidon2::hash[[:space:]]*\(' | wc -l | tr -d ' ')
if [ "$POS" -ne "$BASELINE_POS_SITES" ]; then
  red 5 "Poseidon2::hash surface changed ($POS vs baseline $BASELINE_POS_SITES); confirm each passes message length == array length, then re-baseline."
fi

# Guard 6: Fails if vendored crypto files drift from their frozen sha256 hashes, preventing silent primitive changes.
VENDOR_DIR="$CIRCUITS_DIR/vendor"
HASH_FILE="$VENDOR_DIR/VENDOR-HASHES.sha256"
if [ ! -f "$HASH_FILE" ]; then
  red 6 "vendor hash manifest missing ($HASH_FILE); regenerate it from the vendored tree."
else
  live_hashes=$(find "$VENDOR_DIR" \( -name '*.nr' -o -name 'Nargo.toml' \) | LC_ALL=C sort | xargs sha256sum)
  if ! diff <(printf '%s\n' "$live_hashes") "$HASH_FILE" >/dev/null 2>&1; then
    red 6 "vendored source drift vs VENDOR-HASHES.sha256 (a vendored .nr/Nargo.toml was added, deleted, or edited); revert, or re-baseline only if this is a reviewed vendor bump."
    diff <(printf '%s\n' "$live_hashes") "$HASH_FILE" | sed 's/^/  guard6-drift: /' >&2
  fi
fi

# Guard 7: Forbids symlinks and nested vendor/target directories to prevent evasion of the grep scanner.
if find "$CIRCUITS_DIR" -type l | grep -q .; then
  red 7 "symlink under packages/circuits; circuit source must be real files (a symlinked dir escapes find/grep guards)."
  find "$CIRCUITS_DIR" -type l | sed 's/^/  guard7-symlink: /' >&2
fi
NESTED_MODDIR="$(find "$CIRCUITS_DIR" -type d \( -name vendor -o -name target \) -path '*/src/*')"
if [ -n "$NESTED_MODDIR" ]; then
  red 7 "a 'vendor'/'target' directory nested under a src/ tree evades name-based scanning; rename the module."
  printf '%s\n' "$NESTED_MODDIR" | sed 's/^/  guard7-nested: /' >&2
fi

# Guard 8: Fallback grep check ensuring path dependencies don't resolve outside packages/circuits.
ESCAPES="$(grep -rnE '(^|[^A-Za-z_])path[[:space:]]*=' "$CIRCUITS_DIR" --include=Nargo.toml | grep -vE '/target/' | while IFS= read -r hit; do
  toml="${hit%%:*}"
  val="$(printf '%s\n' "$hit" | grep -oE 'path[[:space:]]*=[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*"([^"]*)"$/\1/')"
  [ -z "$val" ] && continue
  resolved="$(realpath -m "$(dirname "$toml")/$val")"
  case "$resolved/" in "$CIRCUITS_ABS"/*) : ;; *) printf '%s -> %s\n' "$toml" "$val" ;; esac
done)"
if [ -n "$ESCAPES" ]; then
  red 8 "a circuit Nargo.toml path-dep resolves outside packages/circuits; keep every dependency inside the tree."
  printf '%s\n' "$ESCAPES" | sed 's/^/  guard8-escape: /' >&2
fi

# Guard 9: Pins ScalarField occurrences to prevent generic/alias evasion of Guard 1's <64> width check.
SFCNT=$(src_grep 'ScalarField' | decomment | wc -l | tr -d ' ')
if [ "$SFCNT" -ne "$BASELINE_SCALARFIELD_SITES" ]; then
  red 9 "ScalarField surface changed ($SFCNT vs baseline $BASELINE_SCALARFIELD_SITES); confirm no <64> width (direct, aliased, or generic-propagated) is introduced, then re-baseline."
fi

if [ "$fail" -eq 0 ]; then
  echo "circuit-guards: all 10 guards pass (git-dep=0, deep-toml=$DEEP_TOML, scalarfield64=0, msm=0, hasher=0, vendor-hash=ok, structural=ok, path-escape=0, mul-sites=$MUL, poseidon-sites=$POS, scalarfield-sites=$SFCNT)."
fi
exit "$fail"
