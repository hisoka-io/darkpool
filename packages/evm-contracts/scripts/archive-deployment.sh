#!/usr/bin/env bash
# Archive a deployment's complete artifacts for reproducibility
#
# Usage: bash scripts/archive-deployment.sh <deployment-name>
# Example: bash scripts/archive-deployment.sh arbitrumSepolia-2026-03-16T12-00-00
#
# Archives: deployment JSON, secrets, circuit artifacts, verifier sources,
#           ABIs, and version metadata to a local directory, plus the network's
#           SOKA record (<network>-soka-latest.json), Safe record (<network>-safes.json)
#           and, when REGISTER_RESULT points at one, the register-nodes result.
#           Optionally pushes to the hisoka-io/nox-deployments private repo.

set -euo pipefail

DEPLOYMENT_NAME="${1:?Usage: archive-deployment.sh <deployment-name>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTRACTS_DIR="$(dirname "$SCRIPT_DIR")"
CIRCUITS_DIR="$(dirname "$CONTRACTS_DIR")/circuits"
ARCHIVE_BASE="${CONTRACTS_DIR}/deployments/archives"
ARCHIVE_DIR="${ARCHIVE_BASE}/${DEPLOYMENT_NAME}"
DEPLOYMENT_FILE="${CONTRACTS_DIR}/deployments/${DEPLOYMENT_NAME}.json"
NETWORK_NAME="${DEPLOYMENT_NAME%%-*}"
CIRCUITS=(deposit withdraw transfer join split public_claim withdraw_multisig transfer_multisig split_multisig join_multisig swap_intent swap_settle)
VERIFIERS=(DepositVerifier WithdrawVerifier TransferVerifier JoinVerifier SplitVerifier PublicClaimVerifier WithdrawMultisigVerifier TransferMultisigVerifier SplitMultisigVerifier JoinMultisigVerifier KageVerifier)
ABIS=(DarkPool NoxRegistry NoxRewardPool NoxExecutionSandbox NoxEntryPoint HowlPaymentAdapter BundleExecutor ComplianceRegistry MockERC20 SokaToken TimelockController)

if [ ! -f "${DEPLOYMENT_FILE}" ]; then
  echo "ERROR: deployment record not found: ${DEPLOYMENT_FILE}" >&2
  exit 1
fi
if [ -e "${ARCHIVE_DIR}" ]; then
  echo "ERROR: archive target already exists: ${ARCHIVE_DIR}" >&2
  exit 1
fi
for circuit in "${CIRCUITS[@]}"; do
  src="${CIRCUITS_DIR}/target/${circuit}.json"
  if [ ! -f "${src}" ]; then
    echo "ERROR: required circuit artifact not found: ${src}" >&2
    exit 1
  fi
done
for verifier in "${VERIFIERS[@]}"; do
  src="${CONTRACTS_DIR}/contracts/verifiers/${verifier}.sol"
  if [ ! -f "${src}" ]; then
    echo "ERROR: required verifier source not found: ${src}" >&2
    exit 1
  fi
done
for abi in "${ABIS[@]}"; do
  found=$(find "${CONTRACTS_DIR}/artifacts" -name "${abi}.json" -not -name "*.dbg.json" -not -path "*/build-info/*" -print -quit)
  if [ -z "${found}" ]; then
    echo "ERROR: required ABI artifact not found for ${abi}; run hardhat compile first" >&2
    exit 1
  fi
done

echo "Archiving deployment: ${DEPLOYMENT_NAME}"
echo "  Contracts dir: ${CONTRACTS_DIR}"
echo "  Circuits dir:  ${CIRCUITS_DIR}"
echo "  Archive dir:   ${ARCHIVE_DIR}"
echo

mkdir -p "${ARCHIVE_DIR}/circuits" "${ARCHIVE_DIR}/verifiers" "${ARCHIVE_DIR}/abis"

# 1. Copy deployment JSON + secrets
echo "[1/6] Copying deployment records..."
cp "${DEPLOYMENT_FILE}" "${ARCHIVE_DIR}/deployment.json"
if [ -f "${CONTRACTS_DIR}/deployments/${DEPLOYMENT_NAME}.secrets.json" ]; then
  cp "${CONTRACTS_DIR}/deployments/${DEPLOYMENT_NAME}.secrets.json" "${ARCHIVE_DIR}/secrets.json"
  chmod 600 "${ARCHIVE_DIR}/secrets.json"
  echo "  Secrets file copied (chmod 600)"
fi
for pair in "soka:${NETWORK_NAME}-soka-latest.json" "safes:${NETWORK_NAME}-safes.json"; do
  src="${CONTRACTS_DIR}/deployments/${pair#*:}"
  if [ -f "${src}" ]; then
    cp "${src}" "${ARCHIVE_DIR}/${pair%%:*}.json"
    echo "  ${pair%%:*}.json copied from ${pair#*:}"
  fi
done
if [ -n "${REGISTER_RESULT:-}" ]; then
  cp "${REGISTER_RESULT}" "${ARCHIVE_DIR}/registration.json"
  echo "  registration.json copied from ${REGISTER_RESULT}"
fi

# 2. Copy circuit artifacts
echo "[2/6] Copying circuit artifacts..."
for circuit in "${CIRCUITS[@]}"; do
  src="${CIRCUITS_DIR}/target/${circuit}.json"
  cp "$src" "${ARCHIVE_DIR}/circuits/${circuit}.json"
  echo "  ${circuit}.json ($(wc -c < "$src") bytes)"
done

# 3. Copy verifier Solidity sources
echo "[3/6] Copying verifier sources..."
for verifier in "${VERIFIERS[@]}"; do
  src="${CONTRACTS_DIR}/contracts/verifiers/${verifier}.sol"
  cp "$src" "${ARCHIVE_DIR}/verifiers/${verifier}.sol"
  echo "  ${verifier}.sol"
done

# 4. Copy ABIs
echo "[4/6] Copying ABIs..."
for abi in "${ABIS[@]}"; do
  found=$(find "${CONTRACTS_DIR}/artifacts" -name "${abi}.json" -not -name "*.dbg.json" -not -path "*/build-info/*" -print -quit)
  cp "$found" "${ARCHIVE_DIR}/abis/${abi}.json"
  echo "  ${abi}.json"
done

# 5. Record versions
echo "[5/6] Recording version metadata..."
cat > "${ARCHIVE_DIR}/versions.json" << EOF
{
  "archived_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "solidity": "0.8.28",
  "compiler_settings": "resolved per contract in deployment.json versions.solidity and versions.solidityOverrides",
  "noir": "1.0.0-beta.22",
  "bb_js": "5.0.0",
  "hardhat": "$(npx hardhat --version 2>/dev/null || echo 'unknown')",
  "node": "$(node --version 2>/dev/null || echo 'unknown')",
  "archive_name": "${DEPLOYMENT_NAME}"
}
EOF
echo "  versions.json written"

# 6. Compute checksums
echo "[6/6] Computing checksums..."
(cd "${ARCHIVE_DIR}" && find . -type f -not -name "checksums.sha256" | sort | xargs sha256sum > checksums.sha256)
echo "  checksums.sha256 written"

echo
echo "Archive complete: ${ARCHIVE_DIR}"
echo "Contents:"
find "${ARCHIVE_DIR}" -type f | sort | while read f; do
  echo "  $(basename "$f") ($(wc -c < "$f") bytes)"
done

echo
echo "To push to nox-deployments repo:"
echo "  cd /path/to/nox-deployments"
echo "  cp -r ${ARCHIVE_DIR} ./${DEPLOYMENT_NAME}"
echo "  git add . && git commit -m 'archive: ${DEPLOYMENT_NAME}' && git push"
