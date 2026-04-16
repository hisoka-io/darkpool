#!/bin/bash
# Run the NOX Mixnet DeFi E2E integration test against external Anvil.
#
# This script:
#   1. Starts Anvil on port 8545 (if not already running)
#   2. Starts nox mesh server (5 nodes) pointing to Anvil
#   3. Runs the hardhat test with --network localhost
#   4. Cleans up on exit
#
# Usage: NOX_REPO_DIR=/path/to/nox ./test/nox/run_mixnet_e2e.sh

set -euo pipefail
cd "$(dirname "$0")/../.."

ANVIL_PORT=8545
MESH_DATA_DIR="/tmp/nox_mesh_defi"
MESH_BASE_PORT=14000
LOG_DIR="/tmp/nox_defi_e2e_logs"
NOX_SIM_DIR="${NOX_REPO_DIR:?Set NOX_REPO_DIR to the path of your local nox repo}"

cleanup() {
  echo "[cleanup] Stopping mesh and anvil..."
  pkill -f "nox_mesh_server.*${MESH_DATA_DIR}" 2>/dev/null || true
  pkill -f "nox.*config.*${MESH_DATA_DIR}" 2>/dev/null || true
  pkill -f "anvil.*${ANVIL_PORT}.*silent" 2>/dev/null || true
  sleep 1
}
trap cleanup EXIT

mkdir -p "$LOG_DIR"

# 1. Start Anvil
if curl -s -X POST "http://127.0.0.1:${ANVIL_PORT}" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' >/dev/null 2>&1; then
  echo "[anvil] Already running on port ${ANVIL_PORT}"
else
  echo "[anvil] Starting on port ${ANVIL_PORT}..."
  anvil --port "$ANVIL_PORT" --silent > "$LOG_DIR/anvil.log" 2>&1 &
  sleep 2
fi

# 2. Start nox mesh
echo "[mesh] Starting 5-node mesh..."
rm -rf "$MESH_DATA_DIR" && mkdir -p "$MESH_DATA_DIR"

NOX_KEEP_LOGS=1 cargo run --manifest-path "$NOX_SIM_DIR/Cargo.toml" \
  -p nox-sim --bin nox_mesh_server --features dev-node --release -- \
  --nodes 5 --data-dir "$MESH_DATA_DIR" --base-port "$MESH_BASE_PORT" \
  --anvil-port "$ANVIL_PORT" --mix-delay-ms 0 \
  > "$LOG_DIR/mesh_stdout.log" 2> "$LOG_DIR/mesh_server.log" &

# Wait for mesh
for i in $(seq 1 90); do
  [ -f "$MESH_DATA_DIR/mesh_info.json" ] && echo "[mesh] Ready (${i}s)" && break
  sleep 1
done
sleep 3

# Verify ingress
curl -s "http://127.0.0.1:$((MESH_BASE_PORT + 2))/health" >/dev/null && echo "[mesh] Ingress OK" || {
  echo "[mesh] Ingress FAILED"
  exit 1
}

# 3. Run test
echo "[test] Running NoxMixnetE2E with --network localhost..."
export MESH_INFO_PATH="$MESH_DATA_DIR/mesh_info.json"
export DOTENV_CONFIG_QUIET=true
export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--import tsx"

npx hardhat test test/nox/NoxMixnetE2E.test.ts --network localhost --no-compile

echo "[done] All tests complete."
