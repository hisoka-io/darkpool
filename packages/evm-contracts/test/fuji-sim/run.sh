#!/usr/bin/env bash
# The Fuji test-build simulation: seven wallets on the deployed Howl pool, every note and Merkle path served by a
# Raven Howl node following the chain, every wallet graded after every transaction against the pool's own logs.
#
#   run.sh fork <out dir>    rehearsal on an anvil fork of Fuji: a fast wave, then a planted negative control
#                            that must turn red for the planted feed row alone. A fork reads the state it has not
#                            cached at its fork block, which a pruned (non-archive) endpoint keeps for minutes
#                            only, so a long rehearsal outlives its fork; keep SIM_REHEARSAL_ACTIONS small
#   run.sh live <out dir>    the paced run on Fuji itself, SIM_WAVES waves of SIM_WAVE_MINUTES with
#                            SIM_GAP_MINUTES between them; stops at the first failed wave
#   run.sh smoke <out dir>   on Fuji: a Kage swap settled by a registered solver, and a 2-of-3 FROST multisig that
#                            finds its notes through Raven and spends them (SIM_NODE_DATA continues a node's data)
#
# Needs: SIM_RPC_URL (a Fuji endpoint, e.g. scripts/fuji/rpc-relay.mjs; SIM_NODE_RPC_URL, optional, gives the node
# its own), FUJI_DEPLOYER_KEY_FILE (owner of the test
# tokens, funds the agents), SIM_AGENTS (agent keys, created mode 600 on first setup), HOWL_NODE_BIN, RAVEN_SDK,
# RAVEN_WASM. The deployment, token and venue records default to this package's deployments/ directory.
set -euo pipefail

MODE="${1:?fork or live}"
mkdir -p "${2:?out dir}"
OUT="$(cd "$2" && pwd)"
PKG="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$PKG/test/fuji-sim"
cd "$PKG"

: "${SIM_RPC_URL:?}" "${FUJI_DEPLOYER_KEY_FILE:?}" "${SIM_AGENTS:?}" "${HOWL_NODE_BIN:?}" "${RAVEN_SDK:?}" "${RAVEN_WASM:?}"
export SIM_RECORD="${SIM_RECORD:-$PKG/deployments/fuji-latest.json}"
export SIM_TOKENS="${SIM_TOKENS:-$PKG/deployments/fuji-tokens.json}"
export SIM_SEED="${SIM_SEED:-20261111}"
export SIM_NODE_PORT="${SIM_NODE_PORT:-18957}"
export SIM_LOG_MAX_BLOCKS="${SIM_LOG_MAX_BLOCKS:-100}"
export SIM_MAX_CHEATS="${SIM_MAX_CHEATS:-6}"
# 2 gwei: about 12,600 times the Fuji price measured at setup; the run stops rather than pay a spike
export SIM_MAX_GAS_PRICE_WEI="${SIM_MAX_GAS_PRICE_WEI:-2000000000}"
export SIM_SPEND_CAP_WEI="${SIM_SPEND_CAP_WEI:-1500000000000000000}"
export SIM_AGENT_AVAX="${SIM_AGENT_AVAX:-0.15}" SIM_AGENT_TOKENS="${SIM_AGENT_TOKENS:-10000}"
export SIM_WHALE_TOKENS="${SIM_WHALE_TOKENS:-100000}" SIM_ROUTER_TOKENS="${SIM_ROUTER_TOKENS:-100000}"
export DOTENV_CONFIG_QUIET=true
NODE_MAJOR=$(node -e "console.log(process.versions.node.split('.')[0])")
if [ "$NODE_MAJOR" -ge 22 ]; then
  export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--experimental-strip-types --no-warnings"
else
  export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--import tsx"
fi

ANVIL=
# SIM_KEEP_FORK=1 leaves the fork running after a failed rehearsal wave, to trace the failing call against its state
cleanup() {
  local rc=$?
  if [ -n "$ANVIL" ] && [ "${SIM_KEEP_FORK:-0}" = 1 ] && [ "$rc" != 0 ]; then
    echo "fork kept at http://127.0.0.1:${FORK_PORT} (anvil pid $ANVIL)" | tee -a "$OUT/waves.log"
    return
  fi
  [ -z "$ANVIL" ] || kill "$ANVIL" 2>/dev/null || true
}
trap cleanup EXIT

setup() { # network
  npx hardhat run --network "$1" scripts/fuji/sim-setup.ts 2>&1 | tee -a "$OUT/setup.log"
}

wave() { # n final out-subdir -> rc
  local n=$1 final=$2 dir=$3 rc=0
  mkdir -p "$dir"
  SIM_WAVE=$n SIM_FINAL=$final SIM_OUT_DIR="$dir" \
    npx hardhat test test/fuji-sim/FujiSim.test.ts > "$dir/wave.log" 2>&1 || rc=$?
  # The verdict is the wave's own record, not the exit code: hardhat can exit non-zero after mocha has finished
  # (a lazily loaded dependency of its own), so a wave passes when mocha reports it passing with nothing failing
  # and its summary records no failure and no mismatch.
  local verdict=fail
  if grep -aqE '^[[:space:]]*1 passing' "$dir/wave.log" && ! grep -aqE '^[[:space:]]*[0-9]+ failing' "$dir/wave.log" \
    && [ "$(jq -r '(.failure == null) and (.mismatches == 0)' "$dir/summary.json" 2>/dev/null)" = true ]; then
    verdict=pass
  fi
  echo "wave $n: $verdict (exit $rc, $(date -u +%FT%TZ))" | tee -a "$OUT/waves.log"
  [ "$verdict" = pass ]
}

leaf_count() { # rpc
  curl -sf -X POST -H 'content-type: application/json' --data \
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":\"$(jq -r .contracts.darkPool "$SIM_RECORD")\",\"data\":\"0x$(cast sig 'getNextLeafIndex()' | cut -c3-)\"},\"latest\"]}" \
    "$1" | jq -r .result | cast to-dec
}

case "$MODE" in
  fork)
    FORK_PORT="${FORK_PORT:-18958}"
    nohup anvil --fork-url "$SIM_RPC_URL" --port "$FORK_PORT" --chain-id 43113 --silent > "$OUT/anvil.log" 2>&1 &
    ANVIL=$!
    for _ in $(seq 300); do curl -sf -X POST -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' "http://127.0.0.1:$FORK_PORT" > /dev/null && break; sleep 0.2; done
    export SIM_RPC_URL="http://127.0.0.1:$FORK_PORT" FUJI_FORK_URL="http://127.0.0.1:$FORK_PORT"
    export SIM_NODE_RPC_URL="$SIM_RPC_URL"
    export SIM_VENUE="$OUT/venue.json" SIM_STATE_DIR="$OUT/state"
    setup fujiFork
    # SIM_REHEARSAL_ACTIONS=0 runs the negative control alone, on a fresh wallet state
    if [ "${SIM_REHEARSAL_ACTIONS:-24}" != 0 ]; then
      SIM_WAVE_MINUTES=60 SIM_MAX_ACTIONS="${SIM_REHEARSAL_ACTIONS:-24}" SIM_PACE=0 wave 1 1 "$OUT/wave-1"
    fi
    # negative control: the rehearsal's wallets and node carry on, and the next leaf is blanked in every feed
    # answer the wallets get, so the first wallet to own it must come up short at that row and nowhere else
    PLANT=$(leaf_count "$SIM_RPC_URL")
    rm -rf "$OUT/plant-state"
    if [ -d "$OUT/state" ]; then cp -a "$OUT/state" "$OUT/plant-state"; else mkdir -p "$OUT/plant-state"; fi
    rc=0
    SIM_STATE_DIR="$OUT/plant-state" SIM_PLANT_DROP_FEED_LEAF=$PLANT SIM_WAVE_MINUTES=30 SIM_MAX_ACTIONS=8 SIM_PACE=0 \
      wave 2 0 "$OUT/plant" || rc=$?
    [ "$rc" != 0 ] || { echo "plant: the planted feed fault did not turn the run red" >&2; exit 1; }
    python3 "$HERE/check-plant.py" "$OUT/plant/mismatches.jsonl" "$PLANT"
    ;;
  live)
    export SIM_VENUE="${SIM_VENUE:-$PKG/deployments/fuji-sim-venue.json}" SIM_STATE_DIR="${SIM_STATE_DIR:-$OUT/state}"
    export FUJI_RPC_URL="$SIM_RPC_URL"
    : "${SIM_WAVES:?}" "${SIM_WAVE_MINUTES:?}" "${SIM_GAP_MINUTES:?}"
    export SIM_MAX_ACTIONS="${SIM_MAX_ACTIONS:-1000}" SIM_PACE="${SIM_PACE:-1}"
    FIRST=$(( $(jq -r '.wavesDone // 0' "$SIM_STATE_DIR/run.json" 2>/dev/null || echo 0) + 1 ))
    for n in $(seq "$FIRST" "$SIM_WAVES"); do
      setup fuji
      final=0; [ "$n" = "$SIM_WAVES" ] && final=1
      wave "$n" "$final" "$OUT/wave-$n"
      [ "$n" = "$SIM_WAVES" ] || sleep $(( SIM_GAP_MINUTES * 60 ))
    done
    ;;
  smoke)
    export FUJI_RPC_URL="$SIM_RPC_URL"
    dir="$OUT/smoke"
    rc=0
    SIM_OUT_DIR="$dir" npx hardhat test test/fuji-sim/FujiKageMultisig.test.ts > "$OUT/smoke.log" 2>&1 || rc=$?
    # judged by mocha's own summary, as each wave is (hardhat can exit non-zero after mocha has finished)
    verdict=fail
    if grep -aqE '^[[:space:]]*2 passing' "$OUT/smoke.log" && ! grep -aqE '^[[:space:]]*[0-9]+ failing' "$OUT/smoke.log" \
      && [ "$(jq -r '.mismatches == 0' "$dir/summary.json" 2>/dev/null)" = true ]; then
      verdict=pass
    fi
    echo "smoke: $verdict (exit $rc, $(date -u +%FT%TZ))" | tee -a "$OUT/waves.log"
    [ "$verdict" = pass ]
    ;;
  *) echo "unknown mode: $MODE" >&2; exit 2 ;;
esac
