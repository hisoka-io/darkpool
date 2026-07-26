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
  "0x0acd44e1ec48394f150038558d8ee52c0e29412d03c35d9d198fd30914e585f3";
export const INTENT_VK_LEN = 115;
export const INTENT_PROOF_LEN = 458;
export const INTENT_PI_LEN = 27;

// 42 = KageVerifier NUMBER_OF_PUBLIC_INPUTS (50) - PAIRING_POINTS_SIZE (8).
export const SETTLE_PROOF_FIELDS = 322;
export const SETTLE_PI_LEN = 42;
