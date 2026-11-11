#!/usr/bin/env bash
# Dry run of the Avalanche Fuji pre-freeze test build on a local anvil fork of Fuji:
#   test tokens (mUSDC, mWETH, mDAI) -> fresh Gov (3-of-5) and Guardian (2-of-3) Safe owners -> Safes ->
#   deploy.ts (full stack, Kage module on) -> Kage registration through Gov Safe -> Timelock, checked before and
#   after execution -> independent cast wiring checks -> gas priced at the live Fuji gas price.
#
# The deployer is the real Fuji deployer key, read by hardhat.config.ts from FUJI_DEPLOYER_KEY_FILE, so the fork
# reproduces the live addresses. Every transaction goes to the local fork; Fuji is only read (fork source, gas price).
#
# Usage: scripts/fuji/rehearse-fuji.sh <port> <output.json>
# Env:
#   FUJI_DEPLOYER_KEY_FILE  mode-600 file holding the deployer key (never printed)
#   FORK_RPC_URL            fork source (default https://api.avax-test.network/ext/bc/C/rpc)
#   GOV_DELAY_SECS          Timelock and DarkPool admin-transfer delay (default 60)
#
# Writes <output.json> (addresses, gas per step, AVAX cost) and keeps logs, records and the rehearsal-only Safe
# owner keys in <output>.work-<UTC>/.

set -euo pipefail

usage="usage: rehearse-fuji.sh <port> <output.json>"
PORT="${1:?$usage}"
OUT="${2:?$usage}"
FORK_RPC_URL="${FORK_RPC_URL:-https://api.avax-test.network/ext/bc/C/rpc}"
GOV_DELAY_SECS="${GOV_DELAY_SECS:-60}"
CHAIN_ID=43113
NETWORK=fujiFork

cd "$(dirname "$0")/../.."
for tool in anvil cast jq npx; do
  command -v "$tool" >/dev/null || { echo "ERROR: $tool not found on PATH" >&2; exit 1; }
done
[ -n "${FUJI_DEPLOYER_KEY_FILE:-}" ] || { echo "ERROR: FUJI_DEPLOYER_KEY_FILE is required" >&2; exit 1; }
[ "$(stat -c %a "$FUJI_DEPLOYER_KEY_FILE")" = "600" ] || { echo "ERROR: $FUJI_DEPLOYER_KEY_FILE must be mode 600" >&2; exit 1; }
[ "$(cast chain-id --rpc-url "$FORK_RPC_URL")" = "$CHAIN_ID" ] || { echo "ERROR: $FORK_RPC_URL is not Fuji" >&2; exit 1; }

RPC="http://127.0.0.1:${PORT}"
if cast chain-id --rpc-url "$RPC" >/dev/null 2>&1; then
  echo "ERROR: something already answers on port ${PORT}; pick a free port" >&2
  exit 1
fi

OUT_DIR="$(cd "$(dirname "$OUT")" && pwd)"
OUT="${OUT_DIR}/$(basename "$OUT")"
WORK="${OUT%.json}.work-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$WORK/deployments"
chmod 700 "$WORK"
echo "Rehearsal work dir: $WORK"

ANVIL_PID=""
cleanup() { [ -n "$ANVIL_PID" ] && kill "$ANVIL_PID" 2>/dev/null || true; }
trap cleanup EXIT

echo "[1/8] Starting anvil fork of Fuji on ${RPC}..."
anvil --fork-url "$FORK_RPC_URL" --port "$PORT" --chain-id "$CHAIN_ID" --retries 10 \
  --fork-retry-backoff 1000 --timeout 60000 >"$WORK/anvil.log" 2>&1 &
ANVIL_PID=$!
for _ in $(seq 1 90); do
  cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break
  kill -0 "$ANVIL_PID" 2>/dev/null || { echo "ERROR: anvil exited; see $WORK/anvil.log" >&2; exit 1; }
  sleep 1
done
[ "$(cast chain-id --rpc-url "$RPC")" = "$CHAIN_ID" ] || { echo "ERROR: fork chain id is not $CHAIN_ID" >&2; exit 1; }
FORK_BLOCK=$(cast block-number --rpc-url "$RPC")
echo "  fork block ${FORK_BLOCK}"

# Nothing from the operator's shell or .env may steer the rehearsal.
unset GOV_SAFE GUARDIAN_SAFE STAKING_TOKEN KAGE_STAKING_TOKEN FEE_ASSETS SWAP_ROUTER COMPLIANCE_SECRET_KEY \
  COMPLIANCE_PUBLIC_KEY_X COMPLIANCE_PUBLIC_KEY_Y LOCAL_TEST_COMPLIANCE_SECRET_KEY MULTISIG_VERIFIERS \
  KAGE_MODULE KAGE_EXIT_DELAY_SECS FORCE_LAUNCH_RULES ALLOW_REDEPLOY TIMELOCK_SALT WAIT_FOR_DELAY DRY_RUN \
  SAFES_OUT SAFE_SALT_NONCE ALLOW_ALREADY_EXECUTED KAGE_OPERATION_ID NODE_OPTIONS
export FUJI_FORK_URL="$RPC"
export SKIP_EXPLORER_VERIFY=true
export DEPLOYMENTS_DIR="$WORK/deployments"
export DOTENV_CONFIG_QUIET=true

DEPLOYER=$(npx hardhat run --no-compile --network "$NETWORK" scripts/fuji/print-deployer.ts 2>/dev/null | tail -1)
[[ "$DEPLOYER" =~ ^0x[0-9a-fA-F]{40}$ ]] || { echo "ERROR: could not derive the deployer address" >&2; exit 1; }
echo "  deployer ${DEPLOYER} ($(cast balance --ether "$DEPLOYER" --rpc-url "$RPC") AVAX on the fork)"
NONCE_BEFORE=$(cast nonce "$DEPLOYER" --rpc-url "$RPC")

hh() { npx hardhat run --no-compile --network "$NETWORK" "$@"; }
STEPS='[]'
STEP_FROM=0
step_begin() { STEP_FROM=$(($(cast block-number --rpc-url "$RPC") + 1)); }
step_end() {
  local to
  to=$(cast block-number --rpc-url "$RPC")
  STEPS=$(jq -c --arg n "$1" --argjson f "$STEP_FROM" --argjson t "$to" \
    '. + [{name: $n, fromBlock: $f, toBlock: $t}]' <<<"$STEPS")
}
fail() { echo "REHEARSAL FAILED: $*" >&2; exit 1; }

echo "[2/8] Compiling..."
npx hardhat compile >"$WORK/compile.log" 2>&1 || fail "hardhat compile; see $WORK/compile.log"

echo "[3/8] Deploying test tokens..."
step_begin
TOKENS_OUT="$WORK/tokens.json" hh scripts/fuji/deploy-test-tokens.ts | tee "$WORK/tokens.log"
step_end "tokens"
MUSDC=$(jq -r '.tokens.mUSDC.address' "$WORK/tokens.json")
MWETH=$(jq -r '.tokens.mWETH.address' "$WORK/tokens.json")
MDAI=$(jq -r '.tokens.mDAI.address' "$WORK/tokens.json")

echo "[4/8] Generating rehearsal Safe owners and creating Gov and Guardian Safes..."
OWNER_KEYS_OUT="$WORK/owner-keys.json" SAFE_OWNERS_OUT="$WORK/safe-owners.json" \
  hh scripts/gov/generate-owners.ts | tee "$WORK/owners.log"
step_begin
SAFE_OWNERS_FILE="$WORK/safe-owners.json" SAFES_OUT="$WORK/safes.json" \
  hh scripts/gov/create-safes.ts | tee "$WORK/safes.log"
step_end "safes"
GOV=$(jq -r '.gov.address' "$WORK/safes.json")
GUARD=$(jq -r '.guardian.address' "$WORK/safes.json")

echo "[5/8] Deploying the Howl stack (Kage module on, governance delay ${GOV_DELAY_SECS}s)..."
step_begin
GOV_SAFE="$GOV" GUARDIAN_SAFE="$GUARD" STAKING_TOKEN="$MWETH" KAGE_STAKING_TOKEN="$MWETH" \
  FEE_ASSETS="$MUSDC,$MWETH,$MDAI" KAGE_MODULE=on \
  TIMELOCK_MIN_DELAY_SECS="$GOV_DELAY_SECS" ADMIN_TRANSFER_DELAY_SECS="$GOV_DELAY_SECS" \
  hh scripts/deploy.ts | tee "$WORK/deploy.log"
step_end "deploy"
grep -q "Governance topology verified; proceeding to renounce." "$WORK/deploy.log" || fail "deploy preflight"
grep -q "DEPLOYMENT COMPLETE" "$WORK/deploy.log" || fail "deploy did not complete"
if grep -q "\[FAIL\]" "$WORK/deploy.log"; then fail "deploy preflight reported FAIL"; fi
RECORD="$DEPLOYMENTS_DIR/${NETWORK}-latest.json"
[ -f "$RECORD" ] || fail "no deployment record at $RECORD"
TIMELOCK_ADDR=$(jq -r '.governance.timelock' "$RECORD")
DARKPOOL=$(jq -r '.contracts.darkPool' "$RECORD")
START_BLOCK=$(jq -r '.meta.startBlock' "$RECORD")

echo "[6/8] Registering the Kage module through Gov Safe -> Timelock..."
jq '[.kage.moduleRegistration | {to: .target, data: .data}]' "$RECORD" >"$WORK/kage-calls.json"
SAFE="$GOV" OWNER_KEYS_FILE="$WORK/owner-keys.json" CALLS_FILE="$WORK/kage-calls.json" VIA_TIMELOCK="$TIMELOCK_ADDR" \
  DRY_RUN=true hh scripts/gov/safe-exec.ts | tee "$WORK/kage-dry-run.log"
step_begin
SAFE="$GOV" OWNER_KEYS_FILE="$WORK/owner-keys.json" CALLS_FILE="$WORK/kage-calls.json" VIA_TIMELOCK="$TIMELOCK_ADDR" \
  WAIT_FOR_DELAY=false hh scripts/gov/safe-exec.ts | tee "$WORK/kage-schedule.log"
OP_ID=$(grep -oE 'operation 0x[0-9a-f]{64}' "$WORK/kage-schedule.log" | tail -1 | cut -d' ' -f2)
[ -n "$OP_ID" ] || fail "no Timelock operation id in the schedule log"
DEPLOYMENT_RECORD="$RECORD" KAGE_OPERATION_ID="$OP_ID" hh scripts/check-kage-module.ts | tee "$WORK/kage-check-pre.log"
cast rpc evm_increaseTime "$((GOV_DELAY_SECS + 1))" --rpc-url "$RPC" >/dev/null
cast rpc evm_mine --rpc-url "$RPC" >/dev/null
SAFE="$GOV" OWNER_KEYS_FILE="$WORK/owner-keys.json" CALLS_FILE="$WORK/kage-calls.json" VIA_TIMELOCK="$TIMELOCK_ADDR" \
  hh scripts/gov/safe-exec.ts | tee "$WORK/kage-execute.log"
step_end "kage-registration"
DEPLOYMENT_RECORD="$RECORD" hh scripts/check-kage-module.ts | tee "$WORK/kage-check-post.log"

echo "[7/8] Independent wiring checks (cast)..."
CHECKS="$WORK/wiring.txt"
: >"$CHECKS"
check() { if eval "$2"; then echo "PASS $1" | tee -a "$CHECKS"; else echo "FAIL $1" | tee -a "$CHECKS"; fi; }
for name in $(jq -r '.contracts | keys[]' "$RECORD"); do
  addr=$(jq -r --arg n "$name" '.contracts[$n]' "$RECORD")
  [[ "$addr" =~ ^0x[0-9a-fA-F]{40}$ ]] || continue
  check "code at contracts.$name $addr" "[ \"\$(cast code $addr --rpc-url $RPC)\" != 0x ]"
done
for t in mUSDC mWETH mDAI; do
  a=$(jq -r --arg t "$t" '.tokens[$t].address' "$WORK/tokens.json")
  d=$(jq -r --arg t "$t" '.tokens[$t].decimals' "$WORK/tokens.json")
  check "$t decimals $d" "[ \"\$(cast call $a 'decimals()(uint8)' --rpc-url $RPC)\" = $d ]"
  check "$t owner is the deployer" "[ \"\$(cast call $a 'owner()(address)' --rpc-url $RPC | tr A-F a-f)\" = $(tr A-F a-f <<<"$DEPLOYER") ]"
  check "$t symbol marks a test token" "cast call $a 'name()(string)' --rpc-url $RPC | grep -q 'pre-freeze test'"
done
ZERO=0x0000000000000000000000000000000000000000000000000000000000000000
for role in "$ZERO" "$(cast keccak PROPOSER_ROLE)" "$(cast keccak EXECUTOR_ROLE)" "$(cast keccak CANCELLER_ROLE)"; do
  check "deployer holds no Timelock role $role" \
    "[ \"\$(cast call $TIMELOCK_ADDR 'hasRole(bytes32,address)(bool)' $role $DEPLOYER --rpc-url $RPC)\" = false ]"
done
check "Gov Safe proposes to the Timelock" \
  "[ \"\$(cast call $TIMELOCK_ADDR 'hasRole(bytes32,address)(bool)' $(cast keccak PROPOSER_ROLE) $GOV --rpc-url $RPC)\" = true ]"
check "DarkPool admin is not the deployer" \
  "[ \"\$(cast call $DARKPOOL 'hasRole(bytes32,address)(bool)' $ZERO $DEPLOYER --rpc-url $RPC)\" = false ]"
check "Kage module check after execution" "grep -qiE 'registered|matches|ok' $WORK/kage-check-post.log"
NONCE_AFTER=$(cast nonce "$DEPLOYER" --rpc-url "$RPC")
if grep -q '^FAIL' "$CHECKS"; then fail "wiring checks: $(grep -c '^FAIL' "$CHECKS") failed; see $CHECKS"; fi
echo "  $(grep -c '^PASS' "$CHECKS") wiring checks passed"

echo "[8/8] Gas, priced at the live Fuji gas price..."
LIVE_GAS_PRICE=$(cast gas-price --rpc-url "$FORK_RPC_URL")
LIVE_BASE_FEE=$(cast base-fee --rpc-url "$FORK_RPC_URL" 2>/dev/null || echo 0)
STEP_GAS='[]'
TOTAL_GAS=0
TX_COUNT=0
for row in $(jq -c '.[]' <<<"$STEPS"); do
  name=$(jq -r .name <<<"$row"); from=$(jq -r .fromBlock <<<"$row"); to=$(jq -r .toBlock <<<"$row")
  gas=0; n=0
  for b in $(seq "$from" "$to"); do
    for h in $(cast block "$b" --json --rpc-url "$RPC" | jq -r '.transactions[]'); do
      g=$(cast receipt "$h" gasUsed --rpc-url "$RPC")
      gas=$((gas + g)); n=$((n + 1))
    done
  done
  STEP_GAS=$(jq -c --arg n "$name" --argjson g "$gas" --argjson c "$n" '. + [{step: $n, gas: $g, txs: $c}]' <<<"$STEP_GAS")
  TOTAL_GAS=$((TOTAL_GAS + gas)); TX_COUNT=$((TX_COUNT + n))
done
COST_WEI=$(python3 -c "print($TOTAL_GAS * $LIVE_GAS_PRICE)")
COST_AVAX=$(cast from-wei "$COST_WEI")
COST_AT_25_NAVAX=$(cast from-wei "$(python3 -c "print($TOTAL_GAS * 25 * 10**9)")")

jq -n --argjson chainId "$CHAIN_ID" --arg fork "$FORK_RPC_URL" --argjson forkBlock "$FORK_BLOCK" \
  --arg deployer "$DEPLOYER" --argjson nonceBefore "$NONCE_BEFORE" --argjson nonceAfter "$NONCE_AFTER" \
  --arg gov "$GOV" --arg guardian "$GUARD" --slurpfile tokens "$WORK/tokens.json" --slurpfile record "$RECORD" \
  --argjson steps "$STEP_GAS" --argjson totalGas "$TOTAL_GAS" --argjson txs "$TX_COUNT" \
  --arg gasPrice "$LIVE_GAS_PRICE" --arg baseFee "$LIVE_BASE_FEE" --arg cost "$COST_AVAX" --arg cost25 "$COST_AT_25_NAVAX" \
  --arg opId "$OP_ID" --arg startBlock "${START_BLOCK}" --argjson passed "$(grep -c '^PASS' "$CHECKS")" \
  '{label: "Avalanche Fuji pre-freeze test build: dry run on an anvil fork", chainId: $chainId,
    forkSource: $fork, forkBlock: $forkBlock, deployer: $deployer, deployerNonce: {before: $nonceBefore, after: $nonceAfter},
    safes: {gov: $gov, guardian: $guardian}, tokens: $tokens[0].tokens, contracts: $record[0].contracts,
    governance: $record[0].governance, kage: {registrationOperation: $opId},
    poolStartBlockOnFork: $startBlock, wiringChecksPassed: $passed,
    gas: {steps: $steps, total: $totalGas, transactions: $txs},
    liveGasPriceWei: $gasPrice, liveBaseFeeWei: $baseFee,
    costAvaxAtLiveGasPrice: $cost, costAvaxAt25nAvax: $cost25}' >"$OUT"
echo "Gas: ${TOTAL_GAS} over ${TX_COUNT} transactions; ${COST_AVAX} AVAX at the live gas price (${LIVE_GAS_PRICE} wei)."
echo "REHEARSAL OK -> $OUT"
