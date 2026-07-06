#!/bin/bash
# Wrapper script to run Hardhat tests.
# Node 22.6+: use native --experimental-strip-types (fixes tsx workspace bug)
# Node <22.6: fall back to --import tsx
#
# The custom test:fast task runs one mocha instance; a nonzero mocha failure count
# propagates as the process exit code. This wrapper additionally parses the mocha
# summary so a red suite fails CI even if the exit code is ever swallowed, and treats
# a run that never printed a passing summary (crash / no tests) as a failure. It never
# reports green on a nonzero hardhat exit.

set -o pipefail
cd "$(dirname "$0")"

export DOTENV_CONFIG_QUIET=true

NODE_MAJOR=$(node -e "console.log(process.versions.node.split('.')[0])")
if [ "$NODE_MAJOR" -ge 22 ] 2>/dev/null; then
  export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--experimental-strip-types --no-warnings"
else
  export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--import tsx"
fi

LOG_FILE="$(mktemp)"
trap 'rm -f "$LOG_FILE"' EXIT

npx hardhat test:fast "$@" 2>&1 | tee "$LOG_FILE"
HARDHAT_STATUS=${PIPESTATUS[0]}

if [ "$HARDHAT_STATUS" -ne 0 ]; then
  echo "test-parallel: hardhat exited with status $HARDHAT_STATUS" >&2
  exit "$HARDHAT_STATUS"
fi

# Mocha epilogue lines are "<indent>N passing" / "<indent>N failing"; a test title that
# merely contains the word cannot match because the count sits at the start of the line.
FAILING=$(grep -aEo '^[[:space:]]*[0-9]+ failing' "$LOG_FILE" | grep -aEo '[0-9]+' | awk '{s+=$1} END {print s+0}')
PASSING=$(grep -acE '^[[:space:]]*[0-9]+ passing' "$LOG_FILE")

if [ "${FAILING:-0}" -gt 0 ]; then
  echo "test-parallel: mocha reported $FAILING failing test(s)" >&2
  exit 1
fi
if [ "${PASSING:-0}" -eq 0 ]; then
  echo "test-parallel: no mocha 'passing' summary found; the suite did not complete" >&2
  exit 1
fi

exit 0
