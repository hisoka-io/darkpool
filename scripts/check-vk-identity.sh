#!/usr/bin/env bash
# Recompile every circuit from source, re-derive every verification key with native bb, and fail on any
# difference from what is committed:
#   - deployed circuits: VK_HASH of a freshly generated --optimized verifier must equal vk-hashes.json, the
#     frozen vk-hashes.golden.json and the committed verifier, and the generated verifier must be
#     byte-identical to the committed .sol (same derivation as packages/prover/scripts/generate_verifier.js);
#   - the recursively verified swap_intent: its noir-recursive VK hash and width must equal the constants
#     pinned in kage_lib and the prover config.
# A compiled program with no pin, or a pin with no compiled program, also fails. Runs offline: the workspace
# has only path dependencies and is compiled in a temporary copy, so the checkout is never written.
#
# Usage: scripts/check-vk-identity.sh [--circuits-dir DIR] [--golden FILE] [--json OUT]
#   --circuits-dir  Noir workspace to compile (default: packages/circuits)
#   --golden        golden manifest to compare against (default: the committed vk-hashes.golden.json)
#   --json          also write every derived hash to OUT
# Exit: 0 identical, 1 drift, 2 usage or toolchain error.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUITS_DIR="$ROOT/packages/circuits"
VERIFIERS_DIR="$ROOT/packages/evm-contracts/contracts/verifiers"
MANIFEST="$VERIFIERS_DIR/vk-hashes.json"
GOLDEN="$VERIFIERS_DIR/vk-hashes.golden.json"
CIRCUIT_LIST="$ROOT/packages/prover/scripts/circuits.js"
GENERATOR="$ROOT/packages/prover/scripts/generate_verifier.js"
PROVER_CONFIG="$ROOT/packages/prover/src/config.ts"
NARGO_ACTION="$ROOT/.github/actions/setup-nargo/action.yml"
JSON_OUT=""

die() { echo "check-vk-identity: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --circuits-dir) CIRCUITS_DIR="$(cd "${2:?--circuits-dir needs a path}" && pwd)"; shift 2 ;;
    --golden) GOLDEN="$(realpath "${2:?--golden needs a path}")"; shift 2 ;;
    --json) JSON_OUT="$(realpath -m "${2:?--json needs a path}")"; shift 2 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) die "unknown argument '$1' (see --help)" ;;
  esac
done
KAGE_LIB="$CIRCUITS_DIR/kage/kage_lib/src/lib.nr"

for f in "$MANIFEST" "$GOLDEN" "$CIRCUIT_LIST" "$GENERATOR" "$PROVER_CONFIG" "$NARGO_ACTION" "$KAGE_LIB" \
  "$CIRCUITS_DIR/Nargo.toml"; do
  [ -f "$f" ] || die "required file missing: $f"
done
command -v jq >/dev/null || die "jq not found on PATH"
command -v nargo >/dev/null || die "nargo not found on PATH"

# Toolchain pins are read from their single sources, so a bump there is enforced here without an edit.
REQ_BB="$(sed -nE 's/^const BB_VERSION = "([^"]+)";.*/\1/p' "$GENERATOR")"
REQ_NARGO="$(sed -nE 's/^ *default: *([0-9][^ ]*) *$/\1/p' "$NARGO_ACTION")"
[ -n "$REQ_BB" ] || die "could not read BB_VERSION from $GENERATOR"
[ -n "$REQ_NARGO" ] || die "could not read the nargo pin from $NARGO_ACTION"
BB="${BB_NATIVE_PATH:-$HOME/.bb/bb}"
[ -x "$BB" ] || die "native bb not found at $BB (set BB_NATIVE_PATH; install with bbup -v $REQ_BB)"
GOT_BB="$("$BB" --version 2>/dev/null | tr -d '[:space:]')"
[ "$GOT_BB" = "$REQ_BB" ] || die "native bb at $BB is '$GOT_BB', want $REQ_BB"
GOT_NARGO="$(nargo --version | sed -nE 's/^nargo version = (.+)$/\1/p')"
[ "$GOT_NARGO" = "$REQ_NARGO" ] || die "nargo is '$GOT_NARGO', want $REQ_NARGO"

norm_hex() {
  local h="${1#0x}"; h="${h#0X}"; h="$(printf '%s' "$h" | tr 'A-F' 'a-f')"
  [[ "$h" =~ ^[0-9a-f]{1,64}$ ]] || { echo "invalid"; return; }
  printf '0x%064s' "$h" | tr ' ' '0'
}
# Reads `<name> = <hex or number>` even when the value sits on the next line.
read_const() { tr '\n' ' ' < "$2" | grep -oE "$1(: *[A-Za-z0-9]+)? *= *\"?[0-9a-fA-Fx]+" | head -1 | grep -oE '[0-9a-fA-Fx]+$' || true; }
manifest_get() { jq -er --arg k "$1" '.[$k] // empty' "$2" 2>/dev/null || true; }

# name|verifier pairs from the prover's circuit list; "null" marks a circuit verified only in-circuit.
mapfile -t ENTRIES < <(sed -nE 's/.*\{ *name: *"([a-z0-9_]+)", *verifier: *("([A-Za-z0-9_]+\.sol)"|null) *\}.*/\1|\3/p' "$CIRCUIT_LIST")
[ "${#ENTRIES[@]}" -gt 0 ] || die "no circuit entries parsed from $CIRCUIT_LIST"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/ws" "$WORK/out"
tar -C "$CIRCUITS_DIR" --exclude=./target -cf - . | tar -C "$WORK/ws" -xf -
if ! (cd "$WORK/ws" && nargo compile --workspace --force) > "$WORK/compile.log" 2>&1; then
  cat "$WORK/compile.log" >&2
  die "nargo compile --workspace failed in $CIRCUITS_DIR"
fi
TARGET="$WORK/ws/target"

fail=0
drift() { echo "DRIFT: $*"; fail=1; }
declare -A SEEN DERIVED
printf '%-18s %-68s %s\n' "circuit" "derived VK hash" "status"

run_bb() { "$BB" "$@" > "$WORK/bb.log" 2>&1 || { cat "$WORK/bb.log" >&2; die "bb $1 failed: $*"; }; }

evm_names=()
for entry in "${ENTRIES[@]}"; do
  name="${entry%%|*}"; verifier="${entry#*|}"
  SEEN[$name]=1
  artifact="$TARGET/$name.json"
  if [ ! -f "$artifact" ]; then drift "$name is listed in circuits.js but the workspace compiled no such program"; continue; fi
  out="$WORK/out/$name"; mkdir -p "$out"

  if [ -z "$verifier" ]; then
    run_bb write_vk -b "$artifact" -o "$out" -t noir-recursive
    derived="$(norm_hex "$(od -An -tx1 -v "$out/vk_hash" | tr -d ' \n')")"
    DERIVED[$name]="$derived"
    width=$(( $(stat -c %s "$out/vk") / 32 ))
    status="ok"
    for src in "$KAGE_LIB" "$PROVER_CONFIG"; do
      pinned="$(norm_hex "$(read_const INTENT_VK_HASH "$src")")"
      pinned_len="$(read_const INTENT_VK_LEN "$src")"
      [ "$pinned" = "$derived" ] || { drift "$name recursive VK hash $derived != INTENT_VK_HASH $pinned in ${src#"$ROOT"/}"; status="DRIFT"; }
      [ "$pinned_len" = "$width" ] || { drift "$name VK width $width != INTENT_VK_LEN '$pinned_len' in ${src#"$ROOT"/}"; status="DRIFT"; }
    done
    printf '%-18s %-68s %s\n' "$name" "$derived" "$status (noir-recursive, width $width)"
    continue
  fi

  evm_names+=("$name")
  run_bb write_vk -b "$artifact" -o "$out" -t evm
  run_bb write_solidity_verifier -k "$out/vk" -o "$out/$verifier" -t evm --optimized
  derived="$(norm_hex "$(sed -nE 's/.*uint256 constant VK_HASH = (0x[0-9a-fA-F]{64});.*/\1/p' "$out/$verifier")")"
  DERIVED[$name]="$derived"
  status="ok"
  committed="$VERIFIERS_DIR/$verifier"
  committed_hash="$(norm_hex "$(sed -nE 's/.*uint256 constant VK_HASH = (0x[0-9a-fA-F]{64});.*/\1/p' "$committed" 2>/dev/null)")"
  for label in manifest golden; do
    file="$MANIFEST"; [ "$label" = golden ] && file="$GOLDEN"
    want="$(norm_hex "$(manifest_get "$name" "$file")")"
    [ "$want" = "$derived" ] || { drift "$name derived $derived != $label ${want}"; status="DRIFT"; }
  done
  [ "$committed_hash" = "$derived" ] || { drift "$name derived $derived != $verifier VK_HASH $committed_hash"; status="DRIFT"; }
  cmp -s "$out/$verifier" "$committed" || { drift "$name generated $verifier is not byte-identical to the committed file"; status="DRIFT"; }
  printf '%-18s %-68s %s\n' "$name" "$derived" "$status (evm --optimized, $verifier)"
done

for artifact in "$TARGET"/*.json; do
  name="$(basename "$artifact" .json)"
  [ -n "${SEEN[$name]:-}" ] || drift "compiled program $name has no VK pin (add it to packages/prover/scripts/circuits.js)"
done
want_keys="$(printf '%s\n' "${evm_names[@]}" | sort | tr '\n' ' ')"
for file in "$MANIFEST" "$GOLDEN"; do
  keys="$(jq -r 'keys[]' "$file" | sort | tr '\n' ' ')"
  [ "$keys" = "$want_keys" ] || drift "${file#"$ROOT"/} covers [$keys], want exactly [$want_keys]"
done

if [ -n "$JSON_OUT" ]; then
  for name in "${!DERIVED[@]}"; do printf '%s\t%s\n' "$name" "${DERIVED[$name]}"; done | sort \
    | jq -Rn '[inputs | split("\t") | {(.[0]): .[1]}] | add' > "$JSON_OUT"
  echo "wrote $JSON_OUT"
fi

if [ "$fail" -ne 0 ]; then
  echo "VK identity check FAILED: at least one verification key drifted from the committed pins."
  exit 1
fi
echo "VK identity check passed: ${#DERIVED[@]} circuits match the committed pins, ${#evm_names[@]} verifiers byte-identical (bb $GOT_BB, nargo $GOT_NARGO)."
