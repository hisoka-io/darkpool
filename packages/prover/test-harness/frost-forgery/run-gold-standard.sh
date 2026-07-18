#!/usr/bin/env bash
# Gold standard for the ACCEPT path: the ablated-binding forgery must produce a real UltraHonk proof that
# VERIFIES, which is what rules out "the test interpreter was lenient". Needs native bb (~/.bb/bb, 5.0.0).
set -euo pipefail
cd "$(dirname "$0")"

BB="${BB_NATIVE_PATH:-$HOME/.bb/bb}"
[ -x "$BB" ] || { echo "native bb not found at $BB (obtain via bbup -v 5.0.0)"; exit 1; }

nargo execute witness
"$BB" write_vk -b target/frost_forgery.json -o target
"$BB" prove -b target/frost_forgery.json -w target/witness.gz -o target

VK=$(find target -type f -name vk | head -1)
PROOF=$(find target -type f -name proof | head -1)
PI=$(find target -type f -name public_inputs | head -1)

"$BB" verify -k "$VK" -p "$PROOF" -i "$PI"
echo "the forged FROST spend produced a VERIFYING proof under the ablated binding"
