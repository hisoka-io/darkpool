#!/usr/bin/env bash

# Hisoka — Environment Dependency Checker
# Usage:
#   ./check-deps.sh                  Pre-install checks (system tools)
#   ./check-deps.sh --post-install   Post-install checks (npm-installed tools + version pins)
#   ./check-deps.sh --ci             Strict mode: all warnings become failures
#   ./check-deps.sh --ci --post-install   Both flags combined

set -euo pipefail

# --- Parse CLI flags ---
POST_INSTALL=0
STRICT=0
for arg in "$@"; do
    case "$arg" in
        --post-install) POST_INSTALL=1 ;;
        --ci)           STRICT=1 ;;
        --help|-h)
            echo "Usage: $0 [--post-install] [--ci]"
            echo "  --post-install  Validate npm-installed tools and critical version pins"
            echo "  --ci            Strict mode: promote all warnings to failures"
            exit 0
            ;;
        *) echo "Unknown flag: $arg"; exit 1 ;;
    esac
done

# --- Resolve script and project root ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Expected versions ---
REQ_NARGO="1.0.0-beta.19"
REQ_CARGO="1.80.0"
REQ_JUST="1.40.0"
REQ_NODE="18.0.0"
REQ_BBJS="4.0.0-nightly.20260218"
REQ_TS="5.9.2"

# Extract pinned pnpm version from package.json packageManager field
REQ_PNPM=$(grep -o '"pnpm@[^"]*"' "$PROJECT_ROOT/package.json" | sed 's/"pnpm@//' | sed 's/"//')
if [ -z "$REQ_PNPM" ]; then
    REQ_PNPM="10.24.0"
fi

# --- Colors ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

# --- Counters ---
OK_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

echo -e "\n${CYAN}Analyzing Hisoka Environment...${NC}\n"

# Header
printf "${CYAN}%-15s %-25s %-20s %-10s${NC}\n" "Tool" "Current Version" "Required" "Status"
printf "${CYAN}%-15s %-25s %-20s %-10s${NC}\n" "----" "---------------" "--------" "------"

EXIT_CODE=0

# --- Helper: print a row with status coloring ---
print_row() {
    local tool=$1
    local current=$2
    local required=$3
    local status=$4

    # In strict mode, promote WARN to FAIL
    if [ "$STRICT" -eq 1 ] && [ "$status" == "WARN" ]; then
        status="FAIL"
    fi

    if [ "$status" == "OK" ]; then
        COLOR=$GREEN
        OK_COUNT=$((OK_COUNT + 1))
    elif [ "$status" == "WARN" ]; then
        COLOR=$YELLOW
        WARN_COUNT=$((WARN_COUNT + 1))
    else
        COLOR=$RED
        FAIL_COUNT=$((FAIL_COUNT + 1))
        EXIT_CODE=1
    fi

    printf "%-15s %-25s %-20s ${COLOR}%-10s${NC}\n" "$tool" "$current" "$required" "$status"
}

# --- Helper: print an info note (no status) ---
print_note() {
    local msg=$1
    echo -e "  ${DIM}$msg${NC}"
}

# ============================================================
# PRE-INSTALL CHECKS (System Tools)
# ============================================================

# --- 1. Node.js ---
if command -v node &> /dev/null; then
    NODE_VER=$(node -v | sed 's/^v//')
    NODE_MAJOR=$(echo "$NODE_VER" | cut -d. -f1)
    if [ "$NODE_MAJOR" -ge 18 ]; then
        print_row "Node.js" "$NODE_VER" ">=$REQ_NODE" "OK"
        if [ "$NODE_MAJOR" -eq 18 ]; then
            print_note "Node 18: crypto polyfill active for vitest worker threads"
        elif [ "$NODE_MAJOR" -gt 22 ]; then
            print_note "Node >22 detected: verify compatibility with @aztec deps"
        fi
    else
        print_row "Node.js" "$NODE_VER" ">=$REQ_NODE" "FAIL"
    fi
else
    print_row "Node.js" "Not Installed" ">=$REQ_NODE" "FAIL"
fi

# --- 2. Just ---
if command -v just &> /dev/null; then
    JUST_VER=$(just --version | awk '{print $2}')
    if [[ "$JUST_VER" > "$REQ_JUST" ]] || [[ "$JUST_VER" == "$REQ_JUST" ]]; then
        print_row "Just" "$JUST_VER" ">=$REQ_JUST" "OK"
    else
        print_row "Just" "$JUST_VER" ">=$REQ_JUST" "WARN"
    fi
else
    print_row "Just" "Not Installed" ">=$REQ_JUST" "FAIL"
fi

# --- 3. pnpm (exact version from package.json) ---
if command -v pnpm &> /dev/null; then
    PNPM_VER=$(pnpm -v)
    if [ "$PNPM_VER" == "$REQ_PNPM" ]; then
        print_row "pnpm" "$PNPM_VER" "==$REQ_PNPM" "OK"
    elif [[ "$PNPM_VER" == 10* ]]; then
        print_row "pnpm" "$PNPM_VER" "==$REQ_PNPM" "WARN"
        print_note "Expected exact $REQ_PNPM (from package.json packageManager)"
    else
        print_row "pnpm" "$PNPM_VER" "==$REQ_PNPM" "FAIL"
    fi
else
    print_row "pnpm" "Not Installed" "==$REQ_PNPM" "FAIL"
fi

# --- 4. Nargo (exact version) ---
if command -v nargo &> /dev/null; then
    NARGO_VER=$(nargo --version | grep "nargo version" | awk -F' = ' '{print $2}')
    if [ "$NARGO_VER" == "$REQ_NARGO" ]; then
        print_row "Nargo" "$NARGO_VER" "==$REQ_NARGO" "OK"
    else
        print_row "Nargo" "$NARGO_VER" "==$REQ_NARGO" "FAIL"
    fi
else
    print_row "Nargo" "Not Installed" "==$REQ_NARGO" "FAIL"
fi

# --- 5. Cargo + rustc ---
if command -v cargo &> /dev/null; then
    CARGO_VER=$(cargo --version | awk '{print $2}')
    print_row "Cargo" "$CARGO_VER" ">=$REQ_CARGO" "OK"
else
    print_row "Cargo" "Not Installed" ">=$REQ_CARGO" "WARN"
fi

if command -v rustc &> /dev/null; then
    RUSTC_VER=$(rustc --version | awk '{print $2}')
    print_row "rustc" "$RUSTC_VER" ">=$REQ_CARGO" "OK"
else
    print_row "rustc" "Not Installed" ">=$REQ_CARGO" "WARN"
fi

# --- 6. Clippy (needed for just nox-lint) ---
if command -v cargo &> /dev/null && cargo clippy --version &> /dev/null; then
    CLIPPY_VER=$(cargo clippy --version 2>/dev/null | awk '{print $2}')
    print_row "clippy" "$CLIPPY_VER" "Any" "OK"
else
    print_row "clippy" "Not Installed" "Any" "WARN"
    print_note "Install: rustup component add clippy"
fi

# --- 7. cargo-watch (needed for just nox-watch) ---
if command -v cargo-watch &> /dev/null || (command -v cargo &> /dev/null && cargo watch --version &> /dev/null 2>&1); then
    CW_VER=$(cargo watch --version 2>/dev/null | awk '{print $2}' || echo "unknown")
    print_row "cargo-watch" "$CW_VER" "Optional" "OK"
else
    print_row "cargo-watch" "Not Installed" "Optional" "WARN"
    print_note "Install: cargo install cargo-watch"
fi

# --- 8. Foundry (anvil + forge) ---
if command -v anvil &> /dev/null; then
    ANVIL_VER=$(anvil --version 2>/dev/null | head -1 | awk '{print $3}' || echo "unknown")
    print_row "anvil" "$ANVIL_VER" "Optional" "OK"

    # Check if foundry bin is on PATH
    if [[ ":$PATH:" != *":$HOME/.foundry/bin:"* ]]; then
        print_note "Hint: add \$HOME/.foundry/bin to PATH for sim binaries"
    fi
else
    print_row "anvil" "Not Installed" "Optional" "WARN"
    print_note "Install: curl -L https://foundry.paradigm.xyz | bash && foundryup"
fi

if command -v forge &> /dev/null; then
    FORGE_VER=$(forge --version 2>/dev/null | head -1 | awk '{print $3}' || echo "unknown")
    print_row "forge" "$FORGE_VER" "Optional" "OK"
else
    print_row "forge" "Not Installed" "Optional" "WARN"
fi

# --- 9. bb (Barretenberg CLI) ---
if command -v bb &> /dev/null; then
    BB_VER=$(bb --version 2>/dev/null || echo "unknown")
    print_row "bb" "$BB_VER" "Optional" "OK"
    print_note "Note: bb CLI must NOT be used for proof gen (use bb.js only)"
else
    print_row "bb" "Not Installed" "Optional" "WARN"
fi

# --- 10. System libraries ---
if command -v pkg-config &> /dev/null; then
    PKGCFG_VER=$(pkg-config --version 2>/dev/null || echo "unknown")
    print_row "pkg-config" "$PKGCFG_VER" "Required" "OK"

    # Check OpenSSL (needed for Rust ethers build)
    if pkg-config --exists openssl 2>/dev/null; then
        OPENSSL_VER=$(pkg-config --modversion openssl 2>/dev/null || echo "unknown")
        print_row "OpenSSL" "$OPENSSL_VER" "Required" "OK"
    else
        print_row "OpenSSL" "Not Found" "Required" "FAIL"
        print_note "Install: sudo apt install libssl-dev (Debian) or brew install openssl"
    fi
else
    print_row "pkg-config" "Not Installed" "Required" "WARN"
    print_note "Cannot verify OpenSSL without pkg-config"
fi

# --- 11. Trufflehog (optional, for secret scanning) ---
if command -v trufflehog &> /dev/null; then
    TH_VER=$(trufflehog --version 2>/dev/null | awk '{print $2}' || echo "unknown")
    print_row "Trufflehog" "$TH_VER" "Optional" "OK"
else
    print_row "Trufflehog" "Not Installed" "Optional" "WARN"
fi

# --- 12. Direnv & auto-configure ---
if command -v direnv &> /dev/null; then
    DIRENV_VER=$(direnv --version)
    print_row "direnv" "$DIRENV_VER" "Recommended" "OK"

    echo -e "\n${CYAN}Configuring direnv permissions...${NC}"
    if [ -f "$PROJECT_ROOT/.envrc" ]; then
        echo "   -> Allowing root .envrc"
        direnv allow "$PROJECT_ROOT" > /dev/null 2>&1
    fi
    find "$PROJECT_ROOT/packages" -name ".envrc" -type f 2>/dev/null | while read -r file; do
        dir=$(dirname "$file")
        echo "   -> Allowing $dir"
        (cd "$dir" && direnv allow . > /dev/null 2>&1)
    done
else
    print_row "direnv" "Not Installed" "Recommended" "WARN"
fi

# ============================================================
# POST-INSTALL CHECKS (npm-installed tools + version pins)
# ============================================================

if [ "$POST_INSTALL" -eq 1 ]; then
    echo ""
    echo -e "${CYAN}Post-Install Validation (npm-installed tools)${NC}"
    printf "${CYAN}%-15s %-25s %-20s %-10s${NC}\n" "----" "---------------" "--------" "------"

    # Check that we're in the project root with node_modules
    if [ ! -d "$PROJECT_ROOT/node_modules" ]; then
        echo -e "${RED}node_modules not found. Run 'pnpm install' first.${NC}"
        EXIT_CODE=1
    else
        # --- turbo ---
        TURBO_VER=$(cd "$PROJECT_ROOT" && pnpm exec turbo --version 2>/dev/null || echo "")
        if [ -n "$TURBO_VER" ]; then
            print_row "turbo" "$TURBO_VER" "Any" "OK"
        else
            print_row "turbo" "Not Installed" "Any" "FAIL"
        fi

        # --- hardhat ---
        HH_VER=$(cd "$PROJECT_ROOT/packages/evm-contracts" && pnpm exec hardhat --version 2>/dev/null | tr -d '[:space:]' || echo "")
        if [ -n "$HH_VER" ]; then
            print_row "hardhat" "$HH_VER" ">=2.14.0" "OK"
        else
            print_row "hardhat" "Not Installed" ">=2.14.0" "FAIL"
        fi

        # --- vitest ---
        VITEST_VER=$(cd "$PROJECT_ROOT/packages/wallets" && pnpm exec vitest --version 2>/dev/null | head -1 | awk -F'/' '{print $2}' | awk '{print $1}' || echo "")
        if [ -n "$VITEST_VER" ]; then
            print_row "vitest" "$VITEST_VER" "Any" "OK"
        else
            print_row "vitest" "Not Installed" "Any" "FAIL"
        fi

        # --- TypeScript version pin ---
        TSC_VER=$(cd "$PROJECT_ROOT" && pnpm exec tsc --version 2>/dev/null | awk '{print $NF}' || echo "")
        if [ "$TSC_VER" == "$REQ_TS" ]; then
            print_row "TypeScript" "$TSC_VER" "==$REQ_TS" "OK"
        elif [ -n "$TSC_VER" ]; then
            print_row "TypeScript" "$TSC_VER" "==$REQ_TS" "WARN"
            print_note "Expected pinned version $REQ_TS"
        else
            print_row "TypeScript" "Not Installed" "==$REQ_TS" "FAIL"
        fi

        # --- @aztec/bb.js version pin (critical) ---
        BBJS_VER=$(cd "$PROJECT_ROOT" && node -e "
            try {
                const fs = require('fs');
                const p = JSON.parse(fs.readFileSync('packages/prover/node_modules/@aztec/bb.js/package.json', 'utf8'));
                console.log(p.version);
            } catch { console.log(''); }
        " 2>/dev/null || echo "")
        if [ "$BBJS_VER" == "$REQ_BBJS" ]; then
            print_row "@aztec/bb.js" "$BBJS_VER" "==$REQ_BBJS" "OK"
        elif [ -n "$BBJS_VER" ]; then
            print_row "@aztec/bb.js" "$BBJS_VER" "==$REQ_BBJS" "FAIL"
            print_note "CRITICAL: bb.js version mismatch breaks proof verification parity"
        else
            print_row "@aztec/bb.js" "Not Found" "==$REQ_BBJS" "FAIL"
        fi

        # --- @noir-lang/noir_js must match nargo ---
        NOIRJS_VER=$(cd "$PROJECT_ROOT" && node -e "
            try {
                const fs = require('fs');
                const p = JSON.parse(fs.readFileSync('packages/prover/node_modules/@noir-lang/noir_js/package.json', 'utf8'));
                console.log(p.version);
            } catch { console.log(''); }
        " 2>/dev/null || echo "")
        if [ "$NOIRJS_VER" == "$REQ_NARGO" ]; then
            print_row "noir_js" "$NOIRJS_VER" "==$REQ_NARGO" "OK"
        elif [ -n "$NOIRJS_VER" ]; then
            print_row "noir_js" "$NOIRJS_VER" "==$REQ_NARGO" "FAIL"
            print_note "noir_js must match nargo version ($REQ_NARGO)"
        else
            print_row "noir_js" "Not Found" "==$REQ_NARGO" "FAIL"
        fi
    fi
fi

# ============================================================
# SUMMARY
# ============================================================

TOTAL=$((OK_COUNT + WARN_COUNT + FAIL_COUNT))
echo ""
echo -e "${CYAN}Summary${NC}"
printf "  ${GREEN}%d passed${NC}  " "$OK_COUNT"
if [ "$WARN_COUNT" -gt 0 ]; then
    printf "${YELLOW}%d warnings${NC}  " "$WARN_COUNT"
fi
if [ "$FAIL_COUNT" -gt 0 ]; then
    printf "${RED}%d failures${NC}  " "$FAIL_COUNT"
fi
printf "${DIM}(%d total checks)${NC}\n" "$TOTAL"

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}Environment looks good! Running install...${NC}"
    exit 0
else
    echo -e "${RED}Please fix the failing dependencies above.${NC}"
    exit 1
fi
