import { homedir } from "node:os";
import { resolve } from "node:path";

// Kage OUTER (swap_settle) proving + verifier-gen run on native bb; the recursion is excluded from the bb.js WASM
// build. Base circuits + the Kage INNER (swap_intent) proof stay on bb.js.
export const BB_NATIVE_PATH: string =
  process.env.BB_NATIVE_PATH ?? resolve(homedir(), ".bb", "bb");
export const BB_NATIVE_VERSION = "4.0.0-nightly.20260218";

// verify_proof_with_type proof-type: HONK_ZK in bb 4.0.0-nightly (7 is HN_FINAL/HyperNova, which UltraBuilder
// rejects).
export const KAGE_PROOF_TYPE = 6;

// swap_intent recursion artifact widths + the pinned inner vkHash (== kage_lib INTENT_VK_HASH). The golden the
// vkHash-parity gate enforces: swap_intent's compiled recursion vkHash MUST equal this, or the recursion pin is
// stale and swap_settle would reject every real proof.
export const INTENT_VK_HASH =
  "0x00fb71aeb00e890cc5e4e94bbc75ac0043eb2e0eb9e9a333461bf3c0eee38cb2";
export const INTENT_VK_LEN = 115;
export const INTENT_PROOF_LEN = 500;
export const INTENT_PI_LEN = 27;

// swap_settle on-chain proof widths (native bb, -t evm). 42 public inputs = KageVerifier NUMBER_OF_PUBLIC_INPUTS
// (50) - PAIRING_POINTS_SIZE (8).
export const SETTLE_PROOF_FIELDS = 322;
export const SETTLE_PI_LEN = 42;
