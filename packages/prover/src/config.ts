import { homedir } from "node:os";
import { resolve } from "node:path";

// swap_settle (outer) proving/verifier-gen need native bb: recursion is excluded from the bb.js WASM build.
export const BB_NATIVE_PATH: string =
  process.env.BB_NATIVE_PATH ?? resolve(homedir(), ".bb", "bb");
export const BB_NATIVE_VERSION = "5.0.0";

// verify_proof_with_type proof-type: HONK_ZK in bb 4.0.0-nightly (7 is HN_FINAL/HyperNova, which UltraBuilder
// rejects).
export const KAGE_PROOF_TYPE = 6;

// Pinned inner vkHash (== kage_lib INTENT_VK_HASH); the vkHash-parity gate fails if swap_intent's compiled vkHash drifts, else swap_settle rejects every real proof.
export const INTENT_VK_HASH =
  "0x2f282faa1ed7f0c76b2d4dfd8ef8555ad443c8fb448373936bb11a1f2678313b";
export const INTENT_VK_LEN = 115;
export const INTENT_PROOF_LEN = 458;
export const INTENT_PI_LEN = 27;

// swap_settle on-chain proof widths (native bb, -t evm). 42 public inputs = KageVerifier NUMBER_OF_PUBLIC_INPUTS
// (50) - PAIRING_POINTS_SIZE (8).
export const SETTLE_PROOF_FIELDS = 322;
export const SETTLE_PI_LEN = 42;
