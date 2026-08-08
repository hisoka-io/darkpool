#!/usr/bin/env bash
# Fails loudly on an unsupported Node major.
#
# `engines` in package.json is advisory: pnpm prints a warning and continues. That is survivable for
# every other dependency in this repo, but better-sqlite3 is a native module compiled per Node ABI, so
# on the wrong major it fails with ERR_DLOPEN_FAILED / NODE_MODULE_VERSION mismatch / "Module did not
# self-register" across the whole server suite, and those read like defects in the code rather than a
# toolchain mismatch.
set -euo pipefail

MIN_MAJOR=20
MAX_MAJOR=22

actual="$(node -p 'process.versions.node')"
major="${actual%%.*}"

if [ "$major" -lt "$MIN_MAJOR" ] || [ "$major" -gt "$MAX_MAJOR" ]; then
  cat >&2 <<EOF
Unsupported Node version: v${actual}
This repo supports Node ${MIN_MAJOR}.x through ${MAX_MAJOR}.x (see "engines" in package.json).

better-sqlite3 is a native module built against a specific Node ABI. On v${major} it cannot load, and
the failure surfaces as dozens of ERR_DLOPEN_FAILED / NODE_MODULE_VERSION errors that look like code
defects. Switch first, then debug:

  nvm use ${MIN_MAJOR}
  # or, if nvm does not take:
  export PATH="\$HOME/.nvm/versions/node/v${MIN_MAJOR}.19.0/bin:\$PATH"
EOF
  exit 1
fi

echo "node v${actual} is supported (${MIN_MAJOR}.x-${MAX_MAJOR}.x)"
