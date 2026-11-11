#!/usr/bin/env bash
# The Avalanche Fuji pre-freeze test build, as a dry run on a local anvil fork (MODE=fork, the default) or live on
# Fuji (MODE=live):
#   test tokens (mUSDC, mWETH, mDAI) -> fresh Gov (3-of-5) and Guardian (2-of-3) Safe owners -> Safes ->
#   deploy.ts (full stack, Kage module on) -> Kage registration through Gov Safe -> Timelock, checked before and
#   after execution -> independent cast wiring checks -> gas priced at the live Fuji gas price.
#
# The deployer is the real Fuji deployer key, read by hardhat.config.ts from FUJI_DEPLOYER_KEY_FILE, so the fork
# reproduces the live addresses. In fork mode every transaction goes to the local fork and Fuji is only read (fork
# source, gas price). Live mode sends every transaction to Fuji, keeps the deployment records in deployments/, writes
# the Safe owner keys to SECRETS_DIR, and verifies every contract on Snowtrace.
#
# Usage: scripts/fuji/rehearse-fuji.sh <port> <output.json>
#   fork mode: the anvil port; live mode: the port of a local retrying relay (rpc-relay.mjs) in front of Fuji
# Env:
#   FUJI_DEPLOYER_KEY_FILE  mode-600 file holding the deployer key (never printed)
#   MODE                    fork (default) or live
#   SECRETS_DIR             live mode: mode-700 directory for the Safe owner keys and the compliance secret
#   FORK_RPC_URL            Fuji RPC: fork source, and the live endpoint (default https://api.avax-test.network/ext/bc/C/rpc)
#   GOV_DELAY_SECS          Timelock and DarkPool admin-transfer delay (default 60)
#   REUSE_TOKENS_AND_SAFES  live mode: "1" resumes after a failed stack deploy, reusing the recorded test tokens, Safe
#                           owners and Safes (all three records and the owner keys must exist) instead of creating them
#
# Writes <output.json> (addresses, gas per step, AVAX cost) and keeps logs, records and the rehearsal-only Safe
# owner keys in <output>.work-<UTC>/.

set -euo pipefail

usage="usage: rehearse-fuji.sh <port> <output.json>"
PORT="${1:?$usage}"
OUT="${2:?$usage}"
FORK_RPC_URL="${FORK_RPC_URL:-https://api.avax-test.network/ext/bc/C/rpc}"
GOV_DELAY_SECS="${GOV_DELAY_SECS:-60}"
MODE="${MODE:-fork}"
CHAIN_ID=43113
case "$MODE" in
  fork) NETWORK=fujiFork ;;
  live) NETWORK=fuji ;;
  *) echo "ERROR: MODE=$MODE must be fork or live" >&2; exit 1 ;;
esac

cd "$(dirname "$0")/../.."
for tool in anvil cast jq npx; do
  command -v "$tool" >/dev/null || { echo "ERROR: $tool not found on PATH" >&2; exit 1; }
done
[ -n "${FUJI_DEPLOYER_KEY_FILE:-}" ] || { echo "ERROR: FUJI_DEPLOYER_KEY_FILE is required" >&2; exit 1; }
[ "$(stat -c %a "$FUJI_DEPLOYER_KEY_FILE")" = "600" ] || { echo "ERROR: $FUJI_DEPLOYER_KEY_FILE must be mode 600" >&2; exit 1; }
[ "$(cast chain-id --rpc-url "$FORK_RPC_URL")" = "$CHAIN_ID" ] || { echo "ERROR: $FORK_RPC_URL is not Fuji" >&2; exit 1; }

RELAY_PID=""
if [ "$MODE" = live ]; then
  RPC="http://127.0.0.1:${PORT}"
  [ -n "${SECRETS_DIR:-}" ] && [ -d "$SECRETS_DIR" ] || { echo "ERROR: live mode needs SECRETS_DIR" >&2; exit 1; }
  [ "$(stat -c %a "$SECRETS_DIR")" = "700" ] || { echo "ERROR: SECRETS_DIR $SECRETS_DIR must be mode 700" >&2; exit 1; }
else
  RPC="http://127.0.0.1:${PORT}"
  if cast chain-id --rpc-url "$RPC" >/dev/null 2>&1; then
    echo "ERROR: something already answers on port ${PORT}; pick a free port" >&2
    exit 1
  fi
fi

OUT_DIR="$(cd "$(dirname "$OUT")" && pwd)"
OUT="${OUT_DIR}/$(basename "$OUT")"
WORK="${OUT%.json}.work-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$WORK/deployments"
chmod 700 "$WORK"
echo "Work dir: $WORK (mode $MODE)"
if [ "$MODE" = live ]; then
  DEPLOY_DIR="$(pwd)/deployments"
  OWNER_KEYS="$SECRETS_DIR/safe-owner-keys.json"
  if [ "${REUSE_TOKENS_AND_SAFES:-}" = 1 ]; then
    for f in "$OWNER_KEYS" "$(pwd)/deployments/fuji-tokens.json" "$(pwd)/deployments/fuji-safe-owners.json" \
      "$(pwd)/deployments/fuji-safes.json"; do
      [ -f "$f" ] || { echo "ERROR: REUSE_TOKENS_AND_SAFES=1 needs $f" >&2; exit 1; }
    done
  else
    [ -e "$OWNER_KEYS" ] && { echo "ERROR: $OWNER_KEYS exists; a live run creates fresh Safe owners once" >&2; exit 1; }
    [ -e "$(pwd)/deployments/fuji-tokens.json" ] && { echo "ERROR: deployments/fuji-tokens.json exists; tokens are deployed once" >&2; exit 1; }
  fi
else
  DEPLOY_DIR="$WORK/deployments"
  OWNER_KEYS="$WORK/owner-keys.json"
fi
mkdir -p "$DEPLOY_DIR"

ANVIL_PID=""
cleanup() {
  [ -n "$ANVIL_PID" ] && kill "$ANVIL_PID" 2>/dev/null
  [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null
  true
}
trap cleanup EXIT

if [ "$MODE" = fork ]; then
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
else
  echo "[1/8] Live on Fuji via a local relay ${RPC} -> ${FORK_RPC_URL}"
  node scripts/fuji/rpc-relay.mjs "$PORT" "$FORK_RPC_URL" 2>"$WORK/relay.log" &
  RELAY_PID=$!
  for _ in $(seq 1 30); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 1; done
  [ "$(cast chain-id --rpc-url "$RPC")" = "$CHAIN_ID" ] || { echo "ERROR: relay did not come up; see $WORK/relay.log" >&2; exit 1; }
fi
FORK_BLOCK=$(cast block-number --rpc-url "$RPC")
echo "  start block ${FORK_BLOCK}"

# Nothing from the operator's shell or .env may steer the rehearsal.
unset GOV_SAFE GUARDIAN_SAFE STAKING_TOKEN KAGE_STAKING_TOKEN FEE_ASSETS SWAP_ROUTER COMPLIANCE_SECRET_KEY \
  COMPLIANCE_PUBLIC_KEY_X COMPLIANCE_PUBLIC_KEY_Y LOCAL_TEST_COMPLIANCE_SECRET_KEY MULTISIG_VERIFIERS \
  KAGE_MODULE KAGE_EXIT_DELAY_SECS FORCE_LAUNCH_RULES ALLOW_REDEPLOY TIMELOCK_SALT WAIT_FOR_DELAY DRY_RUN \
  SAFES_OUT SAFE_SALT_NONCE ALLOW_ALREADY_EXECUTED KAGE_OPERATION_ID NODE_OPTIONS
export FUJI_FORK_URL="$RPC"
if [ "$MODE" = live ]; then export FUJI_RPC_URL="$RPC"; else export FUJI_RPC_URL="$FORK_RPC_URL"; fi
export DEPLOYMENTS_DIR="$DEPLOY_DIR"
if [ "$MODE" = fork ]; then export SKIP_EXPLORER_VERIFY=true; else unset SKIP_EXPLORER_VERIFY; fi
export DOTENV_CONFIG_QUIET=true

DEPLOYER=$(npx hardhat run --no-compile --network "$NETWORK" scripts/fuji/print-deployer.ts 2>/dev/null | tail -1)
[[ "$DEPLOYER" =~ ^0x[0-9a-fA-F]{40}$ ]] || { echo "ERROR: could not derive the deployer address" >&2; exit 1; }
echo "  deployer ${DEPLOYER} ($(cast balance --ether "$DEPLOYER" --rpc-url "$RPC") AVAX, mode $MODE)"
BALANCE_BEFORE=$(cast balance "$DEPLOYER" --rpc-url "$RPC")
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

REUSE="${REUSE_TOKENS_AND_SAFES:-}"
[ "$MODE" = live ] || REUSE=""
if [ "$REUSE" = 1 ]; then
  echo "[3/8] Reusing the recorded test tokens"
  cp "$DEPLOY_DIR/fuji-tokens.json" "$WORK/tokens.json"
else
echo "[3/8] Deploying test tokens..."
step_begin
TOKENS_OUT="$DEPLOY_DIR/fuji-tokens.json" hh scripts/fuji/deploy-test-tokens.ts | tee "$WORK/tokens.log"
step_end "tokens"
fi
cp "$DEPLOY_DIR/fuji-tokens.json" "$WORK/tokens.json"
MUSDC=$(jq -r '.tokens.mUSDC.address' "$WORK/tokens.json")
MWETH=$(jq -r '.tokens.mWETH.address' "$WORK/tokens.json")
MDAI=$(jq -r '.tokens.mDAI.address' "$WORK/tokens.json")

if [ "$REUSE" = 1 ]; then
  echo "[4/8] Reusing the recorded Gov and Guardian Safes"
else
echo "[4/8] Generating Safe owners and creating Gov and Guardian Safes..."
OWNER_KEYS_OUT="$OWNER_KEYS" SAFE_OWNERS_OUT="$DEPLOY_DIR/fuji-safe-owners.json" \
  hh scripts/gov/generate-owners.ts | tee "$WORK/owners.log"
step_begin
SAFE_OWNERS_FILE="$DEPLOY_DIR/fuji-safe-owners.json" SAFES_OUT="$DEPLOY_DIR/fuji-safes.json" \
  hh scripts/gov/create-safes.ts | tee "$WORK/safes.log"
step_end "safes"
fi
GOV=$(jq -r '.gov.address' "$DEPLOY_DIR/fuji-safes.json")
GUARD=$(jq -r '.guardian.address' "$DEPLOY_DIR/fuji-safes.json")

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
SAFE="$GOV" OWNER_KEYS_FILE="$OWNER_KEYS" CALLS_FILE="$WORK/kage-calls.json" VIA_TIMELOCK="$TIMELOCK_ADDR" \
  DRY_RUN=true hh scripts/gov/safe-exec.ts | tee "$WORK/kage-dry-run.log"
step_begin
SAFE="$GOV" OWNER_KEYS_FILE="$OWNER_KEYS" CALLS_FILE="$WORK/kage-calls.json" VIA_TIMELOCK="$TIMELOCK_ADDR" \
  WAIT_FOR_DELAY=false hh scripts/gov/safe-exec.ts | tee "$WORK/kage-schedule.log"
OP_ID=$(grep -oE 'operation 0x[0-9a-f]{64}' "$WORK/kage-schedule.log" | tail -1 | cut -d' ' -f2)
[ -n "$OP_ID" ] || fail "no Timelock operation id in the schedule log"
DEPLOYMENT_RECORD="$RECORD" KAGE_OPERATION_ID="$OP_ID" hh scripts/check-kage-module.ts | tee "$WORK/kage-check-pre.log"
if [ "$MODE" = fork ]; then
  cast rpc evm_increaseTime "$((GOV_DELAY_SECS + 1))" --rpc-url "$RPC" >/dev/null
  cast rpc evm_mine --rpc-url "$RPC" >/dev/null
else
  echo "  waiting ${GOV_DELAY_SECS}s for the Timelock delay..."
  sleep "$((GOV_DELAY_SECS + 10))"
fi
SAFE="$GOV" OWNER_KEYS_FILE="$OWNER_KEYS" CALLS_FILE="$WORK/kage-calls.json" VIA_TIMELOCK="$TIMELOCK_ADDR" \
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
    for h in $(cast block "$b" --json --full --rpc-url "$RPC" | jq -r --arg d "$(tr A-F a-f <<<"$DEPLOYER")" \
      '.transactions[] | select((.from | ascii_downcase) == $d) | .hash'); do
      g=$(cast receipt "$h" gasUsed --rpc-url "$RPC")
      gas=$((gas + g)); n=$((n + 1))
    done
  done
  STEP_GAS=$(jq -c --arg n "$name" --argjson g "$gas" --argjson c "$n" '. + [{step: $n, gas: $g, txs: $c}]' <<<"$STEP_GAS")
  TOTAL_GAS=$((TOTAL_GAS + gas)); TX_COUNT=$((TX_COUNT + n))
done
COST_WEI=$(python3 -c "print($TOTAL_GAS * $LIVE_GAS_PRICE)")
BALANCE_AFTER=$(cast balance "$DEPLOYER" --rpc-url "$RPC")
SPENT_AVAX=$(cast from-wei "$(python3 -c "print($BALANCE_BEFORE - $BALANCE_AFTER)")")
COST_AVAX=$(cast from-wei "$COST_WEI")
COST_AT_25_NAVAX=$(cast from-wei "$(python3 -c "print($TOTAL_GAS * 25 * 10**9)")")

jq -n --argjson chainId "$CHAIN_ID" --arg fork "$FORK_RPC_URL" --argjson forkBlock "$FORK_BLOCK" \
  --arg deployer "$DEPLOYER" --argjson nonceBefore "$NONCE_BEFORE" --argjson nonceAfter "$NONCE_AFTER" \
  --arg gov "$GOV" --arg guardian "$GUARD" --slurpfile tokens "$WORK/tokens.json" --slurpfile record "$RECORD" \
  --argjson steps "$STEP_GAS" --argjson totalGas "$TOTAL_GAS" --argjson txs "$TX_COUNT" \
  --arg gasPrice "$LIVE_GAS_PRICE" --arg baseFee "$LIVE_BASE_FEE" --arg cost "$COST_AVAX" --arg cost25 "$COST_AT_25_NAVAX" \
  --arg opId "$OP_ID" --arg startBlock "${START_BLOCK}" --argjson passed "$(grep -c '^PASS' "$CHECKS")" \
  --arg mode "$MODE" --arg spent "$SPENT_AVAX" \
  '{label: (if $mode == "live" then "Avalanche Fuji pre-freeze test build (testnet)" else "Avalanche Fuji pre-freeze test build: dry run on an anvil fork" end), mode: $mode, chainId: $chainId,
    forkSource: $fork, forkBlock: $forkBlock, deployer: $deployer, deployerNonce: {before: $nonceBefore, after: $nonceAfter},
    safes: {gov: $gov, guardian: $guardian}, tokens: $tokens[0].tokens, contracts: $record[0].contracts,
    governance: $record[0].governance, kage: {registrationOperation: $opId},
    poolStartBlockOnFork: $startBlock, wiringChecksPassed: $passed,
    gas: {steps: $steps, total: $totalGas, transactions: $txs},
    liveGasPriceWei: $gasPrice, liveBaseFeeWei: $baseFee,
    costAvaxAtLiveGasPrice: $cost, costAvaxAt25nAvax: $cost25, deployerBalanceSpentAvax: $spent}' >"$OUT"
echo "Gas: ${TOTAL_GAS} over ${TX_COUNT} transactions; ${COST_AVAX} AVAX at the live gas price (${LIVE_GAS_PRICE} wei)."
if [ "$MODE" = live ]; then
  echo "[9/9] Snowtrace verification of the contracts deploy.ts does not verify..."
  verify() { npx hardhat verify --network fuji "$@" >>"$WORK/verify.log" 2>&1 && echo "  verified $1" || echo "  verify $1: see $WORK/verify.log"; }
  for t in mUSDC mWETH mDAI; do
    verify "$(jq -r --arg t "$t" '.tokens[$t].address' "$WORK/tokens.json")" \
      "$(jq -r --arg t "$t" '.tokens[$t].name' "$WORK/tokens.json")" "$t" \
      "$(jq -r --arg t "$t" '.tokens[$t].decimals' "$WORK/tokens.json")" "$DEPLOYER"
  done
  for name in darkPool noxRegistry noxRewardPool kageRegistry complianceRegistry; do
    addr=$(jq -r --arg n "$name" '.contracts[$n] // empty' "$RECORD")
    [ -n "$addr" ] && [ "$addr" != null ] && verify "$addr"
  done
  for f in "$DEPLOY_DIR"/fuji-*.secrets.json; do
    [ -f "$f" ] || continue
    install -m 600 "$f" "$SECRETS_DIR/$(basename "$f")"
    cmp -s "$f" "$SECRETS_DIR/$(basename "$f")" && echo "  secrets record copied to $SECRETS_DIR/$(basename "$f")"
  done
fi
echo "RUN OK ($MODE) -> $OUT"
