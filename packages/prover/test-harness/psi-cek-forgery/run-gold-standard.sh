#!/usr/bin/env bash
# Gold standard for the ACCEPT path: the ablated-binding forgery must produce a real UltraHonk proof that
# VERIFIES, which is what rules out "the test interpreter was lenient". Needs native bb (~/.bb/bb, 5.0.0).
set -euo pipefail
cd "$(dirname "$0")"

BB="${BB_NATIVE_PATH:-$HOME/.bb/bb}"
[ -x "$BB" ] || { echo "native bb not found at $BB (obtain via bbup -v 5.0.0)"; exit 1; }

# Wiped rather than overwritten: a stale vk/proof/public_inputs left by an earlier run would still satisfy
# `bb verify` even if generation below silently produced nothing, turning the accept control vacuous.
rm -rf target
nargo execute witness

CIRCUIT=target/psi_cek_forgery.json
WITNESS=target/witness.gz
VK=target/vk
PROOF=target/proof
PI=target/public_inputs

require_file() {
  [ -s "$1" ] || { echo "FAIL: expected artifact $1 is missing or empty ($2)"; exit 1; }
}

require_file "$CIRCUIT" "nargo execute did not emit the compiled circuit"
require_file "$WITNESS" "nargo execute did not emit the witness"

"$BB" write_vk -b "$CIRCUIT" -o target
require_file "$VK" "bb write_vk did not emit a verification key"

"$BB" prove -b "$CIRCUIT" -w "$WITNESS" -o target
require_file "$PROOF" "bb prove did not emit a proof"
require_file "$PI" "bb prove did not emit public inputs"

"$BB" verify -k "$VK" -p "$PROOF" -i "$PI"
echo "the forged psi/CEK mint produced a VERIFYING proof under the ablated binding"
