#!/usr/bin/env bash
# Rehearses the Arbitrum Sepolia cutover from scratch on a local anvil fork:
#   SOKA -> Gov (3-of-5) and Guardian (2-of-3) Safes -> deploy.ts with zero governance delays ->
#   register-nodes (Gov Safe -> Timelock -> registerPrivileged) -> idempotent re-run ->
#   guardian freeze/unfreeze -> repeated Timelock action needs a fresh salt -> independent cast checks ->
#   gas priced for the live chain.
#
# Every transaction goes to the local fork, signed with keys derived from the public anvil test mnemonic.
# Nothing is broadcast to a public chain; public RPCs are only read (fork source, L1 gas pricing).
#
# Usage: scripts/rehearse-fork.sh <port> <output.json> <nodes.json>
# Env:
#   FORK_RPC_URL  fork source (default https://arbitrum-sepolia.gateway.tenderly.co, which serves historical
#                 state; publicnode prunes it within minutes)
#   LIVE_RPC_URL  read-only gas pricing source (default FORK_RPC_URL)
#   FORK_BLOCK    pin the fork block (default latest)
#   NODE_BIN_DIR  directory holding a Node 20-22 binary, put first on PATH (package engines: >=20 <23)
#   KEEP_ANVIL    "true" leaves the fork running afterwards. anvil loads uncached accounts at the fork block for as
#                 long as it runs, so this needs a fork source that serves historical state; checked up front.
#
# Writes <output.json> (addresses, registry state, gas) and keeps logs, records and the rehearsal-only owner
# keys in <output>.work-<UTC>/.

set -euo pipefail

usage="usage: rehearse-fork.sh <port> <output.json> <nodes.json>"
PORT="${1:?$usage}"
OUT="${2:?$usage}"
NODES_FILE="$(realpath "${3:?$usage}")"
FORK_RPC_URL="${FORK_RPC_URL:-https://arbitrum-sepolia.gateway.tenderly.co}"
LIVE_RPC_URL="${LIVE_RPC_URL:-$FORK_RPC_URL}"
CHAIN_ID=421614
NETWORK=arbitrumSepoliaFork
# The public anvil/hardhat development mnemonic. Index 0 deploys and submits, 1-5 own the Gov Safe,
# 6-8 own the Guardian Safe, 9 is the SOKA treasury.
MNEMONIC="test test test test test test test test test test test junk"

cd "$(dirname "$0")/.."
PKG_DIR="$(pwd)"
if [ -n "${NODE_BIN_DIR:-}" ]; then
  export PATH="${NODE_BIN_DIR}:${PATH}"
fi
NODE_MAJOR=$(node -e "console.log(process.versions.node.split('.')[0])")
if [ "$NODE_MAJOR" -lt 20 ] || [ "$NODE_MAJOR" -gt 22 ]; then
  echo "ERROR: Node $(node --version) is outside the package engines (>=20 <23); set NODE_BIN_DIR." >&2
  exit 1
fi
for tool in anvil cast jq npx; do
  command -v "$tool" >/dev/null || { echo "ERROR: $tool not found on PATH" >&2; exit 1; }
done
if [ ! -f "$NODES_FILE" ]; then
  echo "ERROR: nodes file $NODES_FILE not found" >&2
  exit 1
fi

if [ "${KEEP_ANVIL:-false}" = "true" ]; then
  PROBE_BLOCK=$(($(cast block-number --rpc-url "$FORK_RPC_URL") - 5000))
  if ! cast balance 0x0000000000000000000000000000000000000001 --block "$PROBE_BLOCK" \
    --rpc-url "$FORK_RPC_URL" >/dev/null 2>&1; then
    echo "ERROR: KEEP_ANVIL=true needs a fork source that serves historical state, and ${FORK_RPC_URL} has none" \
      "at block ${PROBE_BLOCK}: a kept fork would fail as soon as it loads an uncached account." \
      "Use e.g. FORK_RPC_URL=https://arbitrum-sepolia.gateway.tenderly.co" >&2
    exit 1
  fi
fi

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
cleanup() {
  if [ -n "$ANVIL_PID" ] && [ "${KEEP_ANVIL:-false}" != "true" ]; then
    kill "$ANVIL_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "[1/9] Starting anvil fork of ${FORK_RPC_URL} on ${RPC}..."
anvil --fork-url "$FORK_RPC_URL" ${FORK_BLOCK:+--fork-block-number "$FORK_BLOCK"} \
  --port "$PORT" --chain-id "$CHAIN_ID" --retries 10 --fork-retry-backoff 1000 --timeout 60000 \
  >"$WORK/anvil.log" 2>&1 &
ANVIL_PID=$!
for _ in $(seq 1 90); do
  cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break
  kill -0 "$ANVIL_PID" 2>/dev/null || { echo "ERROR: anvil exited; see $WORK/anvil.log" >&2; exit 1; }
  sleep 1
done
[ "$(cast chain-id --rpc-url "$RPC")" = "$CHAIN_ID" ] || { echo "ERROR: fork chain id is not $CHAIN_ID" >&2; exit 1; }
FORK_BLOCK_NUMBER=$(cast block-number --rpc-url "$RPC")
echo "  fork block ${FORK_BLOCK_NUMBER}"

key_at() { cast wallet private-key "$MNEMONIC" "$1"; }
address_at() { cast wallet address --private-key "$(key_at "$1")"; }

DEPLOYER_KEY=$(key_at 0)
DEPLOYER=$(address_at 0)
TREASURY=$(address_at 9)
jq -n '{owners: []}' >"$WORK/owner-keys.json"
chmod 600 "$WORK/owner-keys.json"
for i in 1 2 3 4 5 6 7 8; do
  label=$([ "$i" -le 5 ] && echo "gov-$i" || echo "guardian-$((i - 5))")
  jq --arg l "$label" --arg a "$(address_at "$i")" --arg k "$(key_at "$i")" \
    '.owners += [{label: $l, address: $a, privateKey: $k}]' "$WORK/owner-keys.json" >"$WORK/owner-keys.tmp"
  mv "$WORK/owner-keys.tmp" "$WORK/owner-keys.json"
  chmod 600 "$WORK/owner-keys.json"
done
jq '{gov: {threshold: 3, owners: [.owners[0:5][].address]},
     guardian: {threshold: 2, owners: [.owners[5:8][].address]}}' \
  "$WORK/owner-keys.json" >"$WORK/safe-owners.json"

# Nothing from the operator's shell or .env may steer the rehearsal.
unset GOV_SAFE GUARDIAN_SAFE STAKING_TOKEN FEE_ASSETS SWAP_ROUTER COMPLIANCE_SECRET_KEY \
  LOCAL_TEST_COMPLIANCE_SECRET_KEY COMPLIANCE_THRESHOLD COMPLIANCE_COMMITTEE_SIZE \
  TIMELOCK_MIN_DELAY_SECS ADMIN_TRANSFER_DELAY_SECS NOX_REGISTRY TIMELOCK TIMELOCK_SALT \
  DEPLOYMENT_FILE REREGISTER_MISMATCHED EXPECT_EXACT_SET DRY_RUN WAIT_FOR_DELAY SAFES_OUT \
  SOKA_TREASURY SOKA_SUPPLY SOKA_OWNER SOKA_REDEPLOY SAFE_SALT_NONCE NODE_OPTIONS ALLOW_ALREADY_EXECUTED
export ARB_SEPOLIA_FORK_URL="$RPC"
export ARB_SEPOLIA_FORK_PRIVATE_KEY="$DEPLOYER_KEY"
export SKIP_EXPLORER_VERIFY=true
export DEPLOYMENTS_DIR="$WORK/deployments"
export DOTENV_CONFIG_QUIET=true

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

echo "[2/9] Compiling..."
npx hardhat compile >"$WORK/compile.log" 2>&1 || fail "hardhat compile; see $WORK/compile.log"

echo "[3/9] Deploying SOKA..."
step_begin
SOKA_TREASURY="$TREASURY" SOKA_OWNER="$TREASURY" SOKA_SUPPLY=1000000000 SOKA_REDEPLOY=true \
  hh scripts/deploy-soka.ts | tee "$WORK/soka.log"
step_end "soka"
SOKA=$(jq -r '.token.address' "$DEPLOYMENTS_DIR/${NETWORK}-soka-latest.json")

echo "[4/9] Creating Gov and Guardian Safes..."
step_begin
SAFE_OWNERS_FILE="$WORK/safe-owners.json" SAFE_SALT_NONCE="$(date +%s)" \
  SAFES_OUT="$WORK/safes.json" hh scripts/gov/create-safes.ts | tee "$WORK/safes.log"
step_end "safes"
GOV=$(jq -r '.gov.address' "$WORK/safes.json")
GUARD=$(jq -r '.guardian.address' "$WORK/safes.json")

echo "[5/9] Deploying the contract set with zero governance delays..."
step_begin
GOV_SAFE="$GOV" GUARDIAN_SAFE="$GUARD" STAKING_TOKEN="$SOKA" FEE_ASSETS="$SOKA" \
  TIMELOCK_MIN_DELAY_SECS=0 ADMIN_TRANSFER_DELAY_SECS=0 \
  hh scripts/deploy.ts | tee "$WORK/deploy.log"
step_end "deploy"
grep -q "Governance topology verified; proceeding to renounce." "$WORK/deploy.log" || fail "deploy preflight"
grep -q "DEPLOYMENT COMPLETE" "$WORK/deploy.log" || fail "deploy did not complete"
if grep -q "\[FAIL\]" "$WORK/deploy.log"; then fail "deploy preflight reported FAIL"; fi
RECORD="$DEPLOYMENTS_DIR/${NETWORK}-latest.json"
REGISTRY=$(jq -r '.contracts.noxRegistry' "$RECORD")
TIMELOCK_ADDR=$(jq -r '.governance.timelock' "$RECORD")
DARKPOOL=$(jq -r '.contracts.darkPool' "$RECORD")
REWARD_POOL=$(jq -r '.contracts.noxRewardPool' "$RECORD")

echo "[6/9] Registering the node set through Gov Safe -> Timelock (dry run first)..."
BEFORE=$(cast block-number --rpc-url "$RPC")
NODES_FILE="$NODES_FILE" OWNER_KEYS_FILE="$WORK/owner-keys.json" DEPLOYMENT_FILE="$RECORD" DRY_RUN=true \
  hh scripts/gov/register-nodes.ts | tee "$WORK/register-dry-run.log"
grep -q "DRY RUN ok" "$WORK/register-dry-run.log" || fail "register dry run"
[ "$(cast block-number --rpc-url "$RPC")" = "$BEFORE" ] || fail "dry run sent a transaction"
step_begin
NODES_FILE="$NODES_FILE" OWNER_KEYS_FILE="$WORK/owner-keys.json" DEPLOYMENT_FILE="$RECORD" \
  EXPECT_EXACT_SET=true REGISTER_OUT="$WORK/register.json" \
  hh scripts/gov/register-nodes.ts | tee "$WORK/register.log"
step_end "register-nodes"

echo "[7/9] Re-running registration (must be a no-op)..."
BEFORE=$(cast block-number --rpc-url "$RPC")
NODES_FILE="$NODES_FILE" OWNER_KEYS_FILE="$WORK/owner-keys.json" DEPLOYMENT_FILE="$RECORD" \
  EXPECT_EXACT_SET=true hh scripts/gov/register-nodes.ts | tee "$WORK/register-rerun.log"
grep -q "Plan: 0 to register, 0 to replace" "$WORK/register-rerun.log" || fail "re-run planned work"
[ "$(cast block-number --rpc-url "$RPC")" = "$BEFORE" ] || fail "re-run sent a transaction"

echo "[8/9] Guardian freeze/unfreeze round trip..."
FIRST=$(jq -r '.nodes[0].address' "$NODES_FILE")
step_begin
GUARDIAN_ACTION=freeze NODE_ADDRESSES="$FIRST" OWNER_KEYS_FILE="$WORK/owner-keys.json" \
  DEPLOYMENT_FILE="$RECORD" hh scripts/gov/guardian.ts | tee "$WORK/guardian-freeze.log"
[ "$(cast call "$REGISTRY" "isActiveRelayer(address)(bool)" "$FIRST" --rpc-url "$RPC")" = "false" ] ||
  fail "freeze left $FIRST active"
GUARDIAN_ACTION=unfreeze NODE_ADDRESSES="$FIRST" OWNER_KEYS_FILE="$WORK/owner-keys.json" \
  DEPLOYMENT_FILE="$RECORD" hh scripts/gov/guardian.ts | tee "$WORK/guardian-unfreeze.log"
step_end "guardian-freeze-unfreeze"
[ "$(cast call "$REGISTRY" "isActiveRelayer(address)(bool)" "$FIRST" --rpc-url "$RPC")" = "true" ] ||
  fail "unfreeze left $FIRST inactive"

echo "[8b/9] Delayed Timelock path: schedule, wait, execute through the Gov Safe..."
# A throwaway 5s Timelock owned by the Gov Safe; the batch raises its own delay, a self-call only the
# Timelock can make, so success is visible on-chain without touching the deployed set.
step_begin
TL_BYTECODE=$(jq -r '.bytecode' artifacts/@openzeppelin/contracts/governance/TimelockController.sol/TimelockController.json)
TL_ARGS=$(cast abi-encode "constructor(uint256,address[],address[],address)" 5 "[$GOV]" "[$GOV]" \
  0x0000000000000000000000000000000000000000)
DELAYED_TL=$(cast send --private-key "$DEPLOYER_KEY" --rpc-url "$RPC" --json \
  --create "${TL_BYTECODE}${TL_ARGS#0x}" | jq -r '.contractAddress')
jq -n --arg t "$DELAYED_TL" '[{to: $t, signature: "updateDelay(uint256)", args: ["7"]}]' >"$WORK/delayed-calls.json"
SAFE="$GOV" OWNER_KEYS_FILE="$WORK/owner-keys.json" CALLS_FILE="$WORK/delayed-calls.json" \
  VIA_TIMELOCK="$DELAYED_TL" WAIT_FOR_DELAY=true hh scripts/gov/safe-exec.ts | tee "$WORK/delayed-timelock.log"
step_end "delayed-timelock-check"
check_delay=$(cast call "$DELAYED_TL" "getMinDelay()(uint256)" --rpc-url "$RPC")
[ "$check_delay" = "7" ] || fail "delayed Timelock batch did not execute (min delay $check_delay)"
grep -q "Outcome: executed" "$WORK/delayed-timelock.log" || fail "delayed Timelock outcome"

echo "[8c/9] Repeating a Timelock action: the default salt must refuse, a fresh salt must run it..."
jq -n --arg r "$REGISTRY" '[{to: $r, signature: "pause()", args: []}]' >"$WORK/pause-calls.json"
jq -n --arg r "$REGISTRY" '[{to: $r, signature: "unpause()", args: []}]' >"$WORK/unpause-calls.json"
gov_exec() {
  SAFE="$GOV" VIA_TIMELOCK="$TIMELOCK_ADDR" OWNER_KEYS_FILE="$WORK/owner-keys.json" CALLS_FILE="$1" \
    hh scripts/gov/safe-exec.ts
}
registry_paused() { cast call "$REGISTRY" "paused()(bool)" --rpc-url "$RPC"; }
gov_exec "$WORK/pause-calls.json" >"$WORK/repeat-pause-1.log" 2>&1 || fail "pause; see $WORK/repeat-pause-1.log"
[ "$(registry_paused)" = "true" ] || fail "pause did not land"
gov_exec "$WORK/unpause-calls.json" >"$WORK/repeat-unpause-1.log" 2>&1 || fail "unpause; see $WORK/repeat-unpause-1.log"
[ "$(registry_paused)" = "false" ] || fail "unpause did not land"
if gov_exec "$WORK/pause-calls.json" >"$WORK/repeat-pause-2.log" 2>&1; then
  fail "a repeated pause with the default salt exited 0; see $WORK/repeat-pause-2.log"
fi
grep -q "already ran earlier" "$WORK/repeat-pause-2.log" || fail "repeated pause did not explain the refusal"
[ "$(registry_paused)" = "false" ] || fail "the refused repeat changed the pause state"
echo "  [ok] repeated pause with the default salt refused, registry still unpaused"
TIMELOCK_SALT=$(cast keccak "rehearsal-pause-2") gov_exec "$WORK/pause-calls.json" >"$WORK/repeat-pause-3.log" 2>&1 ||
  fail "pause with a fresh salt; see $WORK/repeat-pause-3.log"
[ "$(registry_paused)" = "true" ] || fail "pause with a fresh salt did not land"
TIMELOCK_SALT=$(cast keccak "rehearsal-unpause-2") gov_exec "$WORK/unpause-calls.json" >"$WORK/repeat-unpause-2.log" 2>&1 ||
  fail "unpause with a fresh salt; see $WORK/repeat-unpause-2.log"
[ "$(registry_paused)" = "false" ] || fail "unpause with a fresh salt did not land"
echo "  [ok] the same pause/unpause ran again under fresh salts"

echo "[9/9] Independent checks and gas pricing..."
N=$(jq '.nodes | length' "$NODES_FILE")
check() {
  local label="$1" got="$2" want="$3"
  if [ "$got" != "$want" ]; then fail "$label: got $got, want $want"; fi
  echo "  [ok] $label = $got"
}
check "relayerCount" "$(cast call "$REGISTRY" "relayerCount()(uint256)" --rpc-url "$RPC")" "$N"
check "NoxRegistry paused" "$(cast call "$REGISTRY" "paused()(bool)" --rpc-url "$RPC")" "false"
check "DarkPool paused" "$(cast call "$DARKPOOL" "paused()(bool)" --rpc-url "$RPC")" "false"
check "Timelock min delay" "$(cast call "$TIMELOCK_ADDR" "getMinDelay()(uint256)" --rpc-url "$RPC")" "0"
check "staking token" "$(cast call "$REGISTRY" "stakingToken()(address)" --rpc-url "$RPC")" "$SOKA"
check "SOKA fee asset supported" \
  "$(cast call "$REWARD_POOL" "isSupportedAsset(address)(bool)" "$SOKA" --rpc-url "$RPC")" "true"
check "Timelock is registry admin" \
  "$(cast call "$REGISTRY" "defaultAdmin()(address)" --rpc-url "$RPC")" "$TIMELOCK_ADDR"
for i in $(seq 0 $((N - 1))); do
  node_json=$(jq -c ".nodes[$i]" "$NODES_FILE")
  addr=$(jq -r '.address' <<<"$node_json")
  mapfile -t row < <(cast call "$REGISTRY" \
    "relayers(address)(bytes32,string,string,string,uint256,uint256,bool,uint8,bool)" "$addr" --rpc-url "$RPC")
  [ "${row[0]}" = "$(jq -r '.sphinxKey | ascii_downcase' <<<"$node_json")" ] || fail "$addr sphinxKey ${row[0]}"
  [ "${row[1]}" = "$(jq '.url' <<<"$node_json")" ] || fail "$addr url ${row[1]}"
  [ "${row[2]}" = "$(jq '.ingressUrl // ""' <<<"$node_json")" ] || fail "$addr ingressUrl ${row[2]}"
  [ "${row[6]}" = "true" ] && [ "${row[7]}" = "1" ] && [ "${row[8]}" = "false" ] ||
    fail "$addr registered/status/frozen = ${row[6]}/${row[7]}/${row[8]}"
  role=$(cast call "$REGISTRY" "nodeRoles(address)(uint8)" "$addr" --rpc-url "$RPC")
  [ "$role" = "$(jq -r '.role' <<<"$node_json")" ] || fail "$addr role $role"
done
echo "  [ok] all ${N} relayers() rows and roles match ${NODES_FILE}"

echo "$STEPS" >"$WORK/steps.json"
FORK_RPC_URL="$RPC" LIVE_RPC_URL="$LIVE_RPC_URL" STEPS_FILE="$WORK/steps.json" GAS_OUT="$WORK/gas.json" \
  npx tsx scripts/rehearsal-gas-report.ts | tee "$WORK/gas.log"

jq -n \
  --arg port "$PORT" --arg rpc "$RPC" --arg source "$FORK_RPC_URL" --argjson forkBlock "$FORK_BLOCK_NUMBER" \
  --arg finishedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg work "$WORK" --arg deployer "$DEPLOYER" \
  --arg nodesFile "$NODES_FILE" \
  --slurpfile soka "$DEPLOYMENTS_DIR/${NETWORK}-soka-latest.json" \
  --slurpfile safes "$WORK/safes.json" \
  --slurpfile record "$RECORD" \
  --slurpfile register "$WORK/register.json" \
  --slurpfile gas "$WORK/gas.json" \
  '{
    rehearsal: {chainId: 421614, port: ($port | tonumber), rpc: $rpc, forkSource: $source, forkBlock: $forkBlock,
                finishedAt: $finishedAt, workDir: $work, nodesFile: $nodesFile, deployer: $deployer},
    soka: $soka[0].token,
    safes: {gov: $safes[0].gov, guardian: $safes[0].guardian, singleton: $safes[0].singleton,
            proxyFactory: $safes[0].proxyFactory, fallbackHandler: $safes[0].fallbackHandler,
            multiSendCallOnly: $safes[0].multiSendCallOnly},
    deployment: $record[0].meta,
    governance: $record[0].governance,
    contracts: $record[0].contracts,
    feeAssets: $record[0].feeAssets,
    registry: {relayerCount: $register[0].relayerCount, topologyFingerprint: $register[0].topologyFingerprint,
               nodeSetFingerprint: $register[0].nodeSetFingerprint, paused: $register[0].paused,
               operationId: $register[0].operationId, transactions: $register[0].transactions},
    gas: $gas[0]
  }' >"$OUT"

echo
echo "REHEARSAL PASSED"
echo "  Output:   $OUT"
echo "  Work dir: $WORK"
if [ "${KEEP_ANVIL:-false}" = "true" ]; then
  echo "  anvil still running on ${RPC} (pid ${ANVIL_PID})"
fi
