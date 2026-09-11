#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")/../.."

NOX_REPO_DIR="${NOX_REPO_DIR:?Set NOX_REPO_DIR to the current nox-clean checkout}"
NOX_SDK_DIR="${NOX_SDK_DIR:?Set NOX_SDK_DIR to the current nox-sdk checkout}"
ANVIL_PORT="8545"
MESH_BASE_PORT="${MESH_BASE_PORT:-16000}"
ORACLE_PORT="${ORACLE_PORT:-16100}"
NATIVE_PRICE_E8="${NATIVE_PRICE_E8:-200000000000}"
FEE_ASSET_PRICE_E8="${FEE_ASSET_PRICE_E8:-100000000}"
RUN_ROOT="$(mktemp -d /tmp/howl-nox-paid-e2e.XXXXXX)"
MESH_DATA_DIR="${RUN_ROOT}/mesh"
ANVIL_LOG="${RUN_ROOT}/anvil.log"
MESH_LOG="${RUN_ROOT}/mesh.log"
ANVIL_PID=""
MESH_PID=""
MESH_PROCESS_GROUP=""
EXIT_KEY_SCAN_VALUE=""

cleanup() {
  status="$1"
  trap - EXIT
  if [ -n "${MESH_PROCESS_GROUP}" ]; then
    kill -TERM -- "-${MESH_PROCESS_GROUP}" 2>/dev/null || true
    for _ in $(seq 1 50); do
      if ! kill -0 -- "-${MESH_PROCESS_GROUP}" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    kill -KILL -- "-${MESH_PROCESS_GROUP}" 2>/dev/null || true
  fi
  if [ -n "${MESH_PID}" ]; then
    wait "${MESH_PID}" 2>/dev/null || true
  fi
  if [ -n "${ANVIL_PID}" ]; then
    kill "${ANVIL_PID}" 2>/dev/null || true
    wait "${ANVIL_PID}" 2>/dev/null || true
  fi
  if [ "${status}" -ne 0 ] && [ -f "${MESH_LOG}" ]; then
    LOG_PATHS=("${MESH_LOG}")
    while IFS= read -r node_log; do
      LOG_PATHS+=("${node_log}")
    done < <(find "${MESH_DATA_DIR}" -path '*/node.log' -type f 2>/dev/null | sort)
    if [ -n "${EXIT_KEY_SCAN_VALUE}" ] && rg --fixed-strings --quiet "${EXIT_KEY_SCAN_VALUE}" "${LOG_PATHS[@]}"; then
      echo "ERROR: paid mesh log contains the exit private key and was not retained" >&2
    else
      FAILURE_LOG="$(mktemp /tmp/howl-nox-paid-e2e-failure.XXXXXX.log)"
      for log_path in "${LOG_PATHS[@]}"; do
        echo "===== $(basename "$(dirname "${log_path}")")/$(basename "${log_path}") =====" >>"${FAILURE_LOG}"
        sed -n '1,2000p' "${log_path}" >>"${FAILURE_LOG}"
      done
      echo "Paid mesh failure log retained at ${FAILURE_LOG}" >&2
    fi
  fi
  rm -rf "${RUN_ROOT}"
  exit "${status}"
}
trap 'cleanup $?' EXIT

rpc_ready() {
  curl --silent --fail --max-time 1 \
    --header 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
    "http://127.0.0.1:${ANVIL_PORT}" >/dev/null 2>&1
}

tcp_port_in_use() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

for mesh_port in \
  "${MESH_BASE_PORT}" \
  "$((MESH_BASE_PORT + 1))" \
  "$((MESH_BASE_PORT + 2))" \
  "$((MESH_BASE_PORT + 10))" \
  "$((MESH_BASE_PORT + 11))" \
  "$((MESH_BASE_PORT + 20))" \
  "$((MESH_BASE_PORT + 21))" \
  "${ORACLE_PORT}"; do
  if tcp_port_in_use "${mesh_port}"; then
    echo "ERROR: paid mesh port ${mesh_port} is already in use" >&2
    exit 1
  fi
done

if rpc_ready; then
  echo "ERROR: port ${ANVIL_PORT} is already in use; the paid E2E requires a fresh deterministic chain" >&2
  exit 1
fi

anvil --port "${ANVIL_PORT}" --silent >"${ANVIL_LOG}" 2>&1 &
ANVIL_PID=$!
for _ in $(seq 1 30); do
  if rpc_ready; then
    break
  fi
  if ! kill -0 "${ANVIL_PID}" 2>/dev/null; then
    echo "ERROR: Anvil stopped before becoming ready" >&2
    tail -n 200 "${ANVIL_LOG}" >&2
    exit 1
  fi
  sleep 1
done
if ! rpc_ready; then
  echo "ERROR: Anvil did not become ready on port ${ANVIL_PORT}" >&2
  tail -n 200 "${ANVIL_LOG}" >&2
  exit 1
fi

export GOV_SAFE="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
export GUARDIAN_SAFE="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
export LOCAL_TEST_COMPLIANCE_SECRET_KEY="987654321"
npx hardhat run scripts/deploy.ts --network localhost
unset LOCAL_TEST_COMPLIANCE_SECRET_KEY

DEPLOYMENT_RECORD_PATH="$(pwd)/deployments/localhost-latest.json"
read -r REGISTRY_ADDRESS ENTRY_POINT_ADDRESS PAYMENT_ADAPTER_ADDRESS REWARD_POOL_ADDRESS FEE_ASSET_ADDRESS < <(
  node -e '
    const fs = require("node:fs");
    const record = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const contracts = record.contracts;
    process.stdout.write([
      contracts.noxRegistry,
      contracts.noxEntryPoint,
      contracts.howlPaymentAdapter,
      contracts.noxRewardPool,
      contracts.stakingToken,
    ].join(" ") + "\n");
  ' "${DEPLOYMENT_RECORD_PATH}"
)

read -r EXIT_PRIVATE_KEY EXIT_ADDRESS < <(
  node --input-type=module -e '
    import { Wallet } from "ethers";
    const wallet = Wallet.createRandom();
    process.stdout.write(`${wallet.privateKey.slice(2)} ${wallet.address}\n`);
  '
)
export NOX_PAID_MESH_EXIT_PRIVATE_KEY="${EXIT_PRIVATE_KEY}"
EXIT_KEY_SCAN_VALUE="${EXIT_PRIVATE_KEY}"

curl --silent --fail \
  --header 'Content-Type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"method\":\"anvil_setBalance\",\"params\":[\"${EXIT_ADDRESS}\",\"0x8AC7230489E80000\"],\"id\":1}" \
  "http://127.0.0.1:${ANVIL_PORT}" >/dev/null

cargo build --manifest-path "${NOX_REPO_DIR}/Cargo.toml" --release --bin nox
pnpm --dir "${NOX_SDK_DIR}" --filter @hisoka-io/nox-client build

NOX_BINARY="${NOX_REPO_DIR}/target/release/nox"
export RUST_LOG="${RUST_LOG:-info}"
setsid cargo run --manifest-path "${NOX_REPO_DIR}/Cargo.toml" \
  --release -p nox-sim --bin nox_paid_mesh_server -- \
  --nox-binary "${NOX_BINARY}" \
  --data-dir "${MESH_DATA_DIR}" \
  --base-port "${MESH_BASE_PORT}" \
  --oracle-port "${ORACLE_PORT}" \
  --rpc-url "http://127.0.0.1:${ANVIL_PORT}" \
  --chain-id 31337 \
  --registry-address "${REGISTRY_ADDRESS}" \
  --entry-point-address "${ENTRY_POINT_ADDRESS}" \
  --payment-adapter-address "${PAYMENT_ADAPTER_ADDRESS}" \
  --reward-pool-address "${REWARD_POOL_ADDRESS}" \
  --fee-asset-address "${FEE_ASSET_ADDRESS}" \
  --fee-asset-price-id mesh-fee \
  --native-asset-price-id ethereum \
  --native-price-e8 "${NATIVE_PRICE_E8}" \
  --fee-asset-price-e8 "${FEE_ASSET_PRICE_E8}" \
  >"${MESH_LOG}" 2>&1 &
MESH_PID=$!
for _ in $(seq 1 50); do
  candidate_group="$(ps -o pgid= -p "${MESH_PID}" 2>/dev/null | tr -d ' ')"
  if [ "${candidate_group}" = "${MESH_PID}" ]; then
    MESH_PROCESS_GROUP="${candidate_group}"
    break
  fi
  if ! kill -0 "${MESH_PID}" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if [ -z "${MESH_PROCESS_GROUP}" ]; then
  kill -TERM "${MESH_PID}" 2>/dev/null || true
  wait "${MESH_PID}" 2>/dev/null || true
  echo "ERROR: paid mesh did not start as its own process-group leader" >&2
  exit 1
fi

REGISTRATION_MANIFEST_PATH="${MESH_DATA_DIR}/registration_manifest.json"
for _ in $(seq 1 90); do
  if [ -f "${REGISTRATION_MANIFEST_PATH}" ]; then
    break
  fi
  if ! kill -0 "${MESH_PID}" 2>/dev/null; then
    echo "ERROR: paid mesh stopped before requesting chain registration" >&2
    tail -n 200 "${MESH_LOG}" >&2
    exit 1
  fi
  sleep 1
done
if [ ! -f "${REGISTRATION_MANIFEST_PATH}" ]; then
  echo "ERROR: paid mesh did not produce registration_manifest.json" >&2
  tail -n 200 "${MESH_LOG}" >&2
  exit 1
fi

export REGISTRATION_MANIFEST_PATH
export DEPLOYMENT_RECORD_PATH
npx hardhat run test/nox/register_paid_mesh.ts --network localhost

MESH_INFO_PATH="${MESH_DATA_DIR}/mesh_info.json"
for _ in $(seq 1 90); do
  if [ -f "${MESH_INFO_PATH}" ]; then
    break
  fi
  if ! kill -0 "${MESH_PID}" 2>/dev/null; then
    echo "ERROR: paid mesh stopped before becoming ready" >&2
    tail -n 200 "${MESH_LOG}" >&2
    exit 1
  fi
  sleep 1
done
if [ ! -f "${MESH_INFO_PATH}" ]; then
  echo "ERROR: paid mesh did not produce mesh_info.json" >&2
  tail -n 200 "${MESH_LOG}" >&2
  exit 1
fi

if rg --fixed-strings --quiet "${EXIT_PRIVATE_KEY}" \
  "${MESH_LOG}" "${REGISTRATION_MANIFEST_PATH}" "${MESH_INFO_PATH}"; then
  echo "ERROR: exit private key appeared in a public paid-mesh artifact" >&2
  exit 1
fi
unset EXIT_PRIVATE_KEY
unset NOX_PAID_MESH_EXIT_PRIVATE_KEY

export MESH_INFO_PATH
export NOX_SDK_DIR
export REQUIRE_NOX_MESH=1
export NOX_E2E_TIMEOUT_MS="${NOX_E2E_TIMEOUT_MS:-120000}"
export DOTENV_CONFIG_QUIET=true
export NODE_OPTIONS="${NODE_OPTIONS:+${NODE_OPTIONS} }--import tsx"

TEST_ARGS=(test test/nox/NoxMixnetE2E.test.ts --network localhost --no-compile)
if [ -n "${NOX_E2E_GREP:-}" ]; then
  TEST_ARGS+=(--grep "${NOX_E2E_GREP}")
fi
npx hardhat "${TEST_ARGS[@]}"
