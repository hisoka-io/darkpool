import { homedir } from "node:os";
import { resolve } from "node:path";

// swap_settle (outer) proving/verifier-gen need native bb: recursion is excluded from the bb.js WASM build.
export const BB_NATIVE_PATH: string =
  process.env.BB_NATIVE_PATH ?? resolve(homedir(), ".bb", "bb");
export const BB_NATIVE_VERSION = "5.0.0";

// verify_proof_with_type proof-type: 6 = HONK_ZK; 7 (HN_FINAL) is rejected by UltraBuilder.
export const KAGE_PROOF_TYPE = 6;

// Must equal kage_lib INTENT_VK_HASH, or swap_settle rejects every real proof.
export const INTENT_VK_HASH =
  "0x03226d5c217d872b9485096243b63d0560408c7aa2f4c93b75e6ffc5d62c1617";
export const INTENT_VK_LEN = 115;
export const INTENT_PROOF_LEN = 458;
export const INTENT_PI_LEN = 28;

// 44 = KageVerifier NUMBER_OF_PUBLIC_INPUTS (52) - PAIRING_POINTS_SIZE (8).
export const SETTLE_PROOF_FIELDS = 322;
export const SETTLE_PI_LEN = 44;
