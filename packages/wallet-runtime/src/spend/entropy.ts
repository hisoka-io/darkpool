import { Fr } from "@aztec/foundation/fields";
import { isEvenY, publicKey, toBjjScalar } from "@hisoka/wallets";
import { WalletRuntimeError } from "../errors.js";

export interface EntropyPort {
  randomBytes(n: number): Uint8Array;
}

export const cryptoEntropy: EntropyPort = {
  randomBytes(n) {
    const out = new Uint8Array(n);
    globalThis.crypto.getRandomValues(out);
    return out;
  },
};

/** Draws per memo ephemeral before the sampler gives up; an even-y key is hit about every second draw. */
export const MEMO_EPH_MAX_DRAWS = 256;

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * A memo ephemeral: 32 random bytes reduced into the BabyJubJub subgroup, redrawn while zero or while its
 * public key has odd y (only `eph_pub.x` is published). Self ephemerals are never sampled.
 */
export function sampleMemoEphemeral(entropy: EntropyPort): Fr {
  for (let draw = 0; draw < MEMO_EPH_MAX_DRAWS; draw++) {
    const scalar = toBjjScalar(
      new Fr(BigInt(`0x${toHex(entropy.randomBytes(32))}`) % Fr.MODULUS),
    );
    if (scalar.isZero()) continue;
    if (isEvenY(publicKey(scalar))) return scalar;
  }
  throw new WalletRuntimeError(
    "ENTROPY_EXHAUSTED",
    `no non-zero even-y memo ephemeral in ${MEMO_EPH_MAX_DRAWS} draws; the entropy source is not random`,
    { draws: String(MEMO_EPH_MAX_DRAWS) },
  );
}

/** A fresh plan id. */
export function newPlanId(entropy: EntropyPort): string {
  return `0x${toHex(entropy.randomBytes(16))}`;
}
