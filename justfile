default: setup

setup:
  @chmod +x scripts/check-deps.sh
  @./scripts/check-deps.sh
  @pnpm install
  @./scripts/check-deps.sh --post-install
  @pnpm exec husky
  @echo "\nSetup complete."

# --- BUILD ---
build:
  pnpm exec turbo run build

rebuild: clean setup build

clean:
  @echo "Cleaning build artifacts..."
  rm -rf packages/*/dist
  rm -rf packages/*/build
  rm -rf packages/*/out
  rm -rf packages/*/.next
  rm -rf packages/*/artifacts
  rm -rf packages/*/target
  rm -rf packages/*/src/generated
  rm -rf packages/evm-contracts/typechain-types
  rm -rf packages/evm-contracts/cache
  rm -rf .turbo
  rm -rf packages/*/.turbo
  rm -rf packages/circuits/target
  @echo "Clean complete."

clean-all: clean
  @echo "Also removing node_modules..."
  rm -rf node_modules
  rm -rf packages/*/node_modules
  @echo "Full clean complete. Run 'just setup' to reinstall."

# --- TEST ---
test:
  pnpm exec turbo run test

test-fork:
  pnpm exec turbo run test:fork --filter=evm-contracts

test-wallets:
  pnpm exec turbo run test --filter=@hisoka/wallets

# --- QUALITY ---
lint:
  @echo "Linting TypeScript..."
  pnpm exec turbo run lint
  @echo "Linting Solidity..."
  cd packages/evm-contracts && pnpm exec solhint 'contracts/**/*.sol'
  @echo "Linting circuits..."
  cd packages/circuits && nargo fmt --check

circular:
  @echo "Checking circular dependencies..."
  pnpm exec dpdm --no-warning --no-tree --exit-code circular:1 packages/wallets/src/index.ts packages/adaptors/src/index.ts packages/prover/src/index.ts

audit:
  pnpm audit
  @echo "Scanning for secrets..."
  trufflehog filesystem --no-update --fail --exclude-paths .trufflehog-ignore-paths .

fix:
  @echo "Prettier..."
  pnpm run format
  @echo "ESLint fix..."
  pnpm exec turbo run lint:fix
  @echo "Solhint fix..."
  cd packages/evm-contracts && pnpm exec solhint 'contracts/**/*.sol' --fix
  @echo "Noir format..."
  cd packages/circuits && nargo fmt

# --- DEV ---
dev:
  pnpm exec turbo run dev

nargo-check:
  cd packages/circuits && nargo check

