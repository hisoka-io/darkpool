#!/usr/bin/env bash

set -euo pipefail

POST_INSTALL=0
CI_MODE=0
for arg in "$@"; do
    case "$arg" in
        --post-install) POST_INSTALL=1 ;;
        --ci)           CI_MODE=1 ;;
        --help|-h)
            echo "Usage: $0 [--post-install] [--ci]"
            echo "  --post-install  Validate npm-installed tools and critical version pins"
            echo "  --ci            CI runner: skip workstation-only tools, promote every other warning to a failure"
            exit 0
            ;;
        *) echo "Unknown flag: $arg"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

REQ_NARGO="1.0.0-beta.22"
REQ_JUST="1.40.0"
# Single-sourced: the Node range from check-node.sh (better-sqlite3 ABI, mirrors "engines"), the Rust floor
# from the toolchain the Nox workflow builds with.
NODE_MIN_MAJOR=$(sed -nE 's/^MIN_MAJOR=([0-9]+)$/\1/p' "$SCRIPT_DIR/check-node.sh")
NODE_MAX_MAJOR=$(sed -nE 's/^MAX_MAJOR=([0-9]+)$/\1/p' "$SCRIPT_DIR/check-node.sh")
REQ_RUST=$(sed -nE 's/^ *toolchain: *([0-9]+\.[0-9]+\.[0-9]+) *$/\1/p' "$PROJECT_ROOT/.github/workflows/nox-paid-e2e.yml" | head -1)
if [ -z "$NODE_MIN_MAJOR" ] || [ -z "$NODE_MAX_MAJOR" ] || [ -z "$REQ_RUST" ]; then
    echo "check-deps: could not read the Node range from scripts/check-node.sh or the Rust pin from .github/workflows/nox-paid-e2e.yml" >&2
    exit 1
fi
REQ_BBJS="5.0.0"
REQ_BB_NATIVE="5.0.0"
REQ_TS="5.9.2"
REQ_OZ_CONTRACTS="5.6.1"
REQ_OZ_UPGRADEABLE="5.6.1"
REQ_HH_UPGRADES="3.9.1"
REQ_UPGRADES_CORE="1.46.0"

REQ_PNPM=$(grep -o '"pnpm@[^"]*"' "$PROJECT_ROOT/package.json" | sed 's/"pnpm@//' | sed 's/"//')
if [ -z "$REQ_PNPM" ]; then
    REQ_PNPM="10.24.0"
fi

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

OK_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

echo -e "\n${CYAN}Analyzing Hisoka Environment...${NC}\n"

printf "${CYAN}%-15s %-25s %-20s %-10s${NC}\n" "Tool" "Current Version" "Required" "Status"
printf "${CYAN}%-15s %-25s %-20s %-10s${NC}\n" "----" "---------------" "--------" "------"

EXIT_CODE=0

print_row() {
    local tool=$1
    local current=$2
    local required=$3
    local status=$4

    if [ "$CI_MODE" -eq 1 ] && [ "$status" == "WARN" ]; then
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

print_note() {
    local msg=$1
    echo -e "  ${DIM}$msg${NC}"
}

# In --ci mode, rows for tools the checking job does not install are skipped rather than failed.
workstation_only() {
    if [ "$CI_MODE" -eq 1 ]; then
        print_note "$1: skipped in --ci (a CI job installs it where it needs it, or never uses it)"
        return 0
    fi
    return 1
}

# True when $1 >= $2 by version ordering.
version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]; }

NODE_RANGE="${NODE_MIN_MAJOR}.x-${NODE_MAX_MAJOR}.x"
if command -v node &> /dev/null; then
    NODE_VER=$(node -v | sed 's/^v//')
    NODE_MAJOR=$(echo "$NODE_VER" | cut -d. -f1)
    if [ "$NODE_MAJOR" -ge "$NODE_MIN_MAJOR" ] && [ "$NODE_MAJOR" -le "$NODE_MAX_MAJOR" ]; then
        print_row "Node.js" "$NODE_VER" "$NODE_RANGE" "OK"
    else
        print_row "Node.js" "$NODE_VER" "$NODE_RANGE" "FAIL"
        print_note "better-sqlite3 is built per Node ABI; see scripts/check-node.sh"
    fi
else
    print_row "Node.js" "Not Installed" "$NODE_RANGE" "FAIL"
fi

if workstation_only "just"; then
    :
elif command -v just &> /dev/null; then
    JUST_VER=$(just --version | awk '{print $2}')
    if [[ "$JUST_VER" > "$REQ_JUST" ]] || [[ "$JUST_VER" == "$REQ_JUST" ]]; then
        print_row "Just" "$JUST_VER" ">=$REQ_JUST" "OK"
    else
        print_row "Just" "$JUST_VER" ">=$REQ_JUST" "WARN"
    fi
else
    print_row "Just" "Not Installed" ">=$REQ_JUST" "FAIL"
fi

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

# Rust only builds the Nox node for the paid mesh e2e, which pins its own toolchain; core CI never uses it.
check_rust_tool() {
    local label=$1 bin=$2 ver
    if ! command -v "$bin" &> /dev/null; then
        print_row "$label" "Not Installed" ">=$REQ_RUST" "WARN"
        return
    fi
    ver=$("$bin" --version | awk '{print $2}')
    if version_ge "$ver" "$REQ_RUST"; then
        print_row "$label" "$ver" ">=$REQ_RUST" "OK"
    else
        print_row "$label" "$ver" ">=$REQ_RUST" "WARN"
        print_note "Below the Rust toolchain the Nox e2e workflow pins: rustup install $REQ_RUST"
    fi
}
if ! workstation_only "Rust (cargo, rustc, clippy, cargo-watch)"; then
    check_rust_tool "Cargo" cargo
    check_rust_tool "rustc" rustc

    if command -v cargo &> /dev/null && cargo clippy --version &> /dev/null; then
        CLIPPY_VER=$(cargo clippy --version 2>/dev/null | awk '{print $2}')
        print_row "clippy" "$CLIPPY_VER" "Any" "OK"
    else
        print_row "clippy" "Not Installed" "Any" "WARN"
        print_note "Install: rustup component add clippy"
    fi

    if command -v cargo-watch &> /dev/null || (command -v cargo &> /dev/null && cargo watch --version &> /dev/null 2>&1); then
        CW_VER=$(cargo watch --version 2>/dev/null | awk '{print $2}' || echo "unknown")
        print_row "cargo-watch" "$CW_VER" "Optional" "OK"
    else
        print_row "cargo-watch" "Not Installed" "Optional" "WARN"
        print_note "Install: cargo install cargo-watch"
    fi
fi

if ! workstation_only "anvil, forge"; then
    if command -v anvil &> /dev/null; then
        ANVIL_VER=$(anvil --version 2>/dev/null | head -1 | awk '{print $3}' || echo "unknown")
        print_row "anvil" "$ANVIL_VER" "Optional" "OK"

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
fi

# Resolve bb the way generate_verifier.js does; a correct PATH bb would otherwise mask a wrong one here.
BB_NATIVE="${BB_NATIVE_PATH:-$HOME/.bb/bb}"
if [ -x "$BB_NATIVE" ]; then
    # Exact match, not a substring: a glob like *5.0* also accepts 0.85.0, 15.0.0 and 5.0.99-rc.
    BB_VER="$("$BB_NATIVE" --version 2>/dev/null | tr -d '[:space:]')" || BB_VER=""
    [ -n "$BB_VER" ] || BB_VER="unknown"
    if [ "$BB_VER" == "$REQ_BB_NATIVE" ]; then
        print_row "bb (native)" "$BB_VER" "==$REQ_BB_NATIVE" "OK"
    else
        print_row "bb (native)" "$BB_VER" "==$REQ_BB_NATIVE" "FAIL"
        print_note "native bb at $BB_NATIVE is not $REQ_BB_NATIVE. An INSTALLED-but-wrong bb is worse than an absent one: generate_verifier.js reads this exact path and silently emits verifiers whose VK no longer matches bb.js-generated proofs (barretenberg#1649). Absent bb is only a WARN because the generator skips."
        print_note "Install: bbup -v $REQ_BB_NATIVE"
    fi
else
    print_row "bb (native)" "Not Installed" "==$REQ_BB_NATIVE" "WARN"
    print_note "native bb absent at $BB_NATIVE: cannot regenerate --optimized verifiers or run Kage outer proving."
    print_note "Install: bbup -v $REQ_BB_NATIVE (or point BB_NATIVE_PATH at an existing 5.0.0 binary)"
fi

if ! workstation_only "pkg-config, OpenSSL, Trufflehog CLI, direnv"; then
    if command -v pkg-config &> /dev/null; then
        PKGCFG_VER=$(pkg-config --version 2>/dev/null || echo "unknown")
        print_row "pkg-config" "$PKGCFG_VER" "Required" "OK"

        # OpenSSL is needed for the Rust ethers build.
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

    if command -v trufflehog &> /dev/null; then
        TH_VER=$(trufflehog --version 2>/dev/null | awk '{print $2}' || echo "unknown")
        print_row "Trufflehog" "$TH_VER" "Optional" "OK"
    else
        print_row "Trufflehog" "Not Installed" "Optional" "WARN"
    fi

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
fi

if [ "$POST_INSTALL" -eq 1 ]; then
    echo ""
    echo -e "${CYAN}Post-Install Validation (npm-installed tools)${NC}"
    printf "${CYAN}%-15s %-25s %-20s %-10s${NC}\n" "----" "---------------" "--------" "------"

    if [ ! -d "$PROJECT_ROOT/node_modules" ]; then
        echo -e "${RED}node_modules not found. Run 'pnpm install' first.${NC}"
        EXIT_CODE=1
    else
        TURBO_VER=$(cd "$PROJECT_ROOT" && pnpm exec turbo --version 2>/dev/null || echo "")
        if [ -n "$TURBO_VER" ]; then
            print_row "turbo" "$TURBO_VER" "Any" "OK"
        else
            print_row "turbo" "Not Installed" "Any" "FAIL"
        fi

        HH_VER=$(cd "$PROJECT_ROOT/packages/evm-contracts" && pnpm exec hardhat --version 2>/dev/null | tr -d '[:space:]' || echo "")
        if [ -n "$HH_VER" ]; then
            print_row "hardhat" "$HH_VER" ">=2.14.0" "OK"
        else
            print_row "hardhat" "Not Installed" ">=2.14.0" "FAIL"
        fi

        VITEST_VER=$(cd "$PROJECT_ROOT/packages/wallets" && pnpm exec vitest --version 2>/dev/null | head -1 | awk -F'/' '{print $2}' | awk '{print $1}' || echo "")
        if [ -n "$VITEST_VER" ]; then
            print_row "vitest" "$VITEST_VER" "Any" "OK"
        else
            print_row "vitest" "Not Installed" "Any" "FAIL"
        fi

        TSC_VER=$(cd "$PROJECT_ROOT" && pnpm exec tsc --version 2>/dev/null | awk '{print $NF}' || echo "")
        if [ "$TSC_VER" == "$REQ_TS" ]; then
            print_row "TypeScript" "$TSC_VER" "==$REQ_TS" "OK"
        elif [ -n "$TSC_VER" ]; then
            print_row "TypeScript" "$TSC_VER" "==$REQ_TS" "WARN"
            print_note "Expected pinned version $REQ_TS"
        else
            print_row "TypeScript" "Not Installed" "==$REQ_TS" "FAIL"
        fi

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

        # contracts and contracts-upgradeable must be exact and equal: their ERC-7201 storage-layout
        # assumptions diverge if the two drift apart.
        check_oz_pin() {
            local label=$1 rel=$2 want=$3
            local got
            got=$(cd "$PROJECT_ROOT" && node -e "
                try { console.log(JSON.parse(require('fs').readFileSync('$rel','utf8')).version); } catch { console.log(''); }
            " 2>/dev/null || echo "")
            if [ "$got" == "$want" ]; then
                print_row "$label" "$got" "==$want" "OK"
            elif [ -n "$got" ]; then
                print_row "$label" "$got" "==$want" "FAIL"
                print_note "OZ upgradeability pin must be exact ($want)"
            else
                print_row "$label" "Not Found" "==$want" "FAIL"
            fi
        }
        OZ_NM="packages/evm-contracts/node_modules/@openzeppelin"
        check_oz_pin "@oz/contracts" "$OZ_NM/contracts/package.json" "$REQ_OZ_CONTRACTS"
        check_oz_pin "@oz/upgradeable" "$OZ_NM/contracts-upgradeable/package.json" "$REQ_OZ_UPGRADEABLE"
        check_oz_pin "hardhat-upgrades" "$OZ_NM/hardhat-upgrades/package.json" "$REQ_HH_UPGRADES"
        check_oz_pin "upgrades-core" "$OZ_NM/upgrades-core/package.json" "$REQ_UPGRADES_CORE"
    fi
fi

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
    echo -e "${GREEN}Environment looks good.${NC}"
    exit 0
else
    echo -e "${RED}Please fix the failing dependencies above.${NC}"
    exit 1
fi
