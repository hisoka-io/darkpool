import { asDerivedEph, type DerivedEph } from "../types/ephemeral";
import { toFr } from "../crypto/fields";
import { isEvenY, publicKey } from "../note/keys";

const evenYScalars: bigint[] = [];

/**
 * The `seed`-th scalar (from 1 upward) whose public key has even y, standing in for a wallet derivation in
 * fixtures that need a fixed self ephemeral the circuits accept. Injective, so distinct seeds stay distinct.
 */
export function canonicalSelfEph(seed: bigint): DerivedEph {
  let next =
    evenYScalars.length === 0 ? 1n : evenYScalars[evenYScalars.length - 1] + 1n;
  while (BigInt(evenYScalars.length) <= seed) {
    if (isEvenY(publicKey(toFr(next)))) evenYScalars.push(next);
    next += 1n;
  }
  return asDerivedEph(toFr(evenYScalars[Number(seed)]));
}
