#!/usr/bin/env bash
# Archive a deployment's complete artifacts for reproducibility
#
# Usage: bash scripts/archive-deployment.sh <deployment-name>
# Example: bash scripts/archive-deployment.sh arbitrumSepolia-2026-03-16T12-00-00
#
# Archives: deployment JSON, secrets, circuit artifacts, verifier sources,
#           ABIs, and version metadata to a local directory.
#           Optionally pushes to the hisoka-io/nox-deployments private repo.

set -euo pipefail

DEPLOYMENT_NAME="${1:?Usage: archive-deployment.sh <deployment-name>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTRACTS_DIR="$(dirname "$SCRIPT_DIR")"
CIRCUITS_DIR="$(dirname "$CONTRACTS_DIR")/circuits"
ARCHIVE_BASE="${CONTRACTS_DIR}/deployments/archives"
ARCHIVE_DIR="${ARCHIVE_BASE}/${DEPLOYMENT_NAME}"

echo "Archiving deployment: ${DEPLOYMENT_NAME}"
echo "  Contracts dir: ${CONTRACTS_DIR}"
echo "  Circuits dir:  ${CIRCUITS_DIR}"
echo "  Archive dir:   ${ARCHIVE_DIR}"
echo

# Create archive structure
mkdir -p "${ARCHIVE_DIR}/circuits" "${ARCHIVE_DIR}/verifiers" "${ARCHIVE_DIR}/abis"

# 1. Copy deployment JSON + secrets
echo "[1/6] Copying deployment records..."
cp "${CONTRACTS_DIR}/deployments/${DEPLOYMENT_NAME}.json" "${ARCHIVE_DIR}/deployment.json" 2>/dev/null || true
if [ -f "${CONTRACTS_DIR}/deployments/${DEPLOYMENT_NAME}.secrets.json" ]; then
  cp "${CONTRACTS_DIR}/deployments/${DEPLOYMENT_NAME}.secrets.json" "${ARCHIVE_DIR}/secrets.json"
  chmod 600 "${ARCHIVE_DIR}/secrets.json"
  echo "  Secrets file copied (chmod 600)"
fi

# 2. Copy circuit artifacts
echo "[2/6] Copying circuit artifacts..."
for circuit in deposit withdraw transfer join split public_claim gas_payment; do
  src="${CIRCUITS_DIR}/target/${circuit}.json"
  if [ -f "$src" ]; then
    cp "$src" "${ARCHIVE_DIR}/circuits/${circuit}.json"
    echo "  ${circuit}.json ($(wc -c < "$src") bytes)"
  else
    echo "  WARNING: ${circuit}.json not found at ${src}"
  fi
done

# 3. Copy verifier Solidity sources
echo "[3/6] Copying verifier sources..."
for verifier in DepositVerifier WithdrawVerifier TransferVerifier JoinVerifier SplitVerifier PublicClaimVerifier GasPaymentVerifier; do
  src="${CONTRACTS_DIR}/contracts/verifiers/${verifier}.sol"
  if [ -f "$src" ]; then
    cp "$src" "${ARCHIVE_DIR}/verifiers/${verifier}.sol"
    echo "  ${verifier}.sol"
  fi
done

# 4. Copy ABIs
echo "[4/6] Copying ABIs..."
for abi in DarkPool NoxRegistry NoxRewardPool MockERC20 RelayerMulticall; do
  # Find the ABI in artifacts
  found=$(find "${CONTRACTS_DIR}/artifacts" -name "${abi}.json" -not -name "*.dbg.json" -not -path "*/build-info/*" | head -1)
  if [ -n "$found" ]; then
    cp "$found" "${ARCHIVE_DIR}/abis/${abi}.json"
    echo "  ${abi}.json"
  fi
done

# 5. Record versions
echo "[5/6] Recording version metadata..."
cat > "${ARCHIVE_DIR}/versions.json" << EOF
{
  "archived_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "solidity": "0.8.25",
  "optimizer": { "enabled": true, "runs": 1 },
  "noir": "1.0.0-beta.19",
  "bb_js": "4.0.0-nightly.20260218",
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
