import { Fr } from "@aztec/foundation/fields";
import type { Point } from "@zk-kit/baby-jubjub";

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

export interface DerivedSelfMintCandidate {
  readonly eph: DerivedEph;
  readonly ephPub: Point<bigint>;
  readonly tag: Fr;
  readonly index: number;
}

interface DerivedSelfMintProvenance {
  readonly ownerCommitment: bigint;
  readonly eph: bigint;
  readonly ephPub: readonly [bigint, bigint];
  readonly tag: bigint;
  readonly index: number;
  readonly memberId: bigint | null;
  readonly j: bigint | null;
  claimed: boolean;
}

const derivedSelfMintProvenance = new WeakMap<
  object,
  DerivedSelfMintProvenance
>();

function optionalBigInt(candidate: object, key: string): bigint | null {
  const value = Reflect.get(candidate, key);
  if (value === undefined) return null;
  if (typeof value !== "bigint") {
    throw new Error(`self-mint candidate ${key} must be a bigint`);
  }
  return value;
}

export function markDerivedSelfMintCandidate<
  T extends DerivedSelfMintCandidate,
>(candidate: T, ownerCommitment: Fr): T {
  derivedSelfMintProvenance.set(candidate, {
    ownerCommitment: ownerCommitment.toBigInt(),
    eph: candidate.eph.toBigInt(),
    ephPub: [candidate.ephPub[0], candidate.ephPub[1]],
    tag: candidate.tag.toBigInt(),
    index: candidate.index,
    memberId: optionalBigInt(candidate, "memberId"),
    j: optionalBigInt(candidate, "j"),
    claimed: false,
  });
  return candidate;
}

export type DerivedSelfMintClaim =
  | "CLAIMED"
  | "UNKNOWN"
  | "OWNER_MISMATCH"
  | "PROVENANCE_MISMATCH"
  | "ALREADY_CLAIMED";

export function claimDerivedSelfMintCandidate(
  candidate: object,
  ownerCommitment: bigint,
): DerivedSelfMintClaim {
  const provenance = derivedSelfMintProvenance.get(candidate);
  if (provenance === undefined) return "UNKNOWN";
  if (provenance.ownerCommitment !== ownerCommitment) return "OWNER_MISMATCH";
  if (
    !(Reflect.get(candidate, "eph") instanceof Fr) ||
    !(Reflect.get(candidate, "tag") instanceof Fr) ||
    !Array.isArray(Reflect.get(candidate, "ephPub"))
  ) {
    return "PROVENANCE_MISMATCH";
  }
  const typed = candidate as DerivedSelfMintCandidate;
  let memberId: bigint | null;
  let j: bigint | null;
  try {
    memberId = optionalBigInt(candidate, "memberId");
    j = optionalBigInt(candidate, "j");
  } catch {
    return "PROVENANCE_MISMATCH";
  }
  if (
    typed.eph.toBigInt() !== provenance.eph ||
    typed.ephPub[0] !== provenance.ephPub[0] ||
    typed.ephPub[1] !== provenance.ephPub[1] ||
    typed.tag.toBigInt() !== provenance.tag ||
    typed.index !== provenance.index ||
    memberId !== provenance.memberId ||
    j !== provenance.j
  ) {
    return "PROVENANCE_MISMATCH";
  }
  if (provenance.claimed) return "ALREADY_CLAIMED";
  provenance.claimed = true;
  return "CLAIMED";
}
