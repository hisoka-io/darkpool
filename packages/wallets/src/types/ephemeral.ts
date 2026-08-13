import { Fr } from "@aztec/foundation/fields";

declare const derivedEphBrand: unique symbol;

/**
 * A self, deposit or change ephemeral that was DERIVED from wallet key material, never sampled.
 *
 * This family's discovery tag is the ephemeral's own public x, and the scalar never travels, so a random
 * one produces a note nobody can find or spend from the seed alone, silently, with the wallet simply
 * reporting a smaller balance. Only the derivation helpers may construct this type, which is what keeps
 * a bare scalar out of a self note.
 *
 * Incoming and memo ephemerals are legitimately random and stay bare `Fr`: their tag is the recipient's
 * key and `cek_wrap` travels with the note, so a random one is both discoverable and spendable.
 * Conflating the two families is the mistake that produced the original defect.
 *
 * The brand is additive: a `DerivedEph` flows into every existing `Fr` parameter unchanged, and only the
 * dangerous direction, a bare `Fr` reaching a self-family sink, is rejected.
 */
export type DerivedEph = Fr & { readonly [derivedEphBrand]: "DerivedEph" };

/**
 * Marks a scalar as derived. Call this ONLY at a derivation site, never on a value that reached the
 * caller from outside: this function is the whole trust boundary the type expresses.
 */
export function asDerivedEph(eph: Fr): DerivedEph {
  return eph as DerivedEph;
}
