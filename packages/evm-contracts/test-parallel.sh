#!/bin/bash
# Wrapper script to run Hardhat tests.
# Node 22.6+: use native --experimental-strip-types (fixes tsx workspace bug)
# Node <22.6: fall back to --import tsx

cd "$(dirname "$0")"

export DOTENV_CONFIG_QUIET=true

NODE_MAJOR=$(node -e "console.log(process.versions.node.split('.')[0])")
if [ "$NODE_MAJOR" -ge 22 ] 2>/dev/null; then
  export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--experimental-strip-types --no-warnings"
else
  export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--import tsx"
fi

exec npx hardhat test:fast "$@"
