import { Fr } from "@aztec/foundation/fields";
import { Base8, mulPointEscalar, Point } from "@zk-kit/baby-jubjub";
import { Kdf } from "../crypto/Kdf.js";
import { Poseidon } from "../crypto/Poseidon.js";
import { toFr } from "../crypto/fields.js";
import { toBjjScalar } from "../crypto/index.js";

const VIEW_LABEL = "hisoka.view";
const IN_KEY_LABEL = "hisoka.inKey";
const SELF_EPH_LABEL = "hisoka.selfEph";
const SELF_SPEND_LABEL = "hisoka.selfSpend";

// even-y rejection sampling terminates in ~2 steps (each index is even-y with prob ~1/2); this bound only
// guards a non-terminating loop and is reached with prob ~2^-MAX_INDEX_ROLL.
const MAX_INDEX_ROLL = 256n;

export interface CanonicalAddress {
  index: bigint;
  pub: Point<bigint>;
  tag: Fr;
}

export async function deriveViewKey(sk_root: Fr): Promise<Fr> {
  return Kdf.derive(VIEW_LABEL, sk_root);
}

export async function deriveIncomingKey(
  sk_view: Fr,
  index: bigint,
): Promise<Fr> {
  return toBjjScalar(await Kdf.derive(IN_KEY_LABEL, sk_view, toFr(index)));
}

export async function deriveSelfEphemeral(
  sk_view: Fr,
  index: bigint,
): Promise<Fr> {
  return toBjjScalar(await Kdf.derive(SELF_EPH_LABEL, sk_view, toFr(index)));
}

export async function deriveSelfSpendKey(sk_view: Fr): Promise<Fr> {
  return toBjjScalar(await Kdf.derive(SELF_SPEND_LABEL, sk_view));
}

export function publicKey(scalar: Fr): Point<bigint> {
  return mulPointEscalar(Base8, scalar.toBigInt());
}

// owner = Poseidon2(pub.x, pub.y); pass in_pub_j for an incoming note, self_spend_pub for a self note.
export async function pubkeyOwner(pub: Point<bigint>): Promise<Fr> {
  return Poseidon.hash([new Fr(pub[0]), new Fr(pub[1])]);
}

// A discovery tag is the point's .x, which aliases (x, +/-y); it is an injective Raven key only when y is
// even. Ref: intmax2 utils/key.rs even-y address canonicalization.
export function isEvenY(pub: Point<bigint>): boolean {
  return (pub[1] & 1n) === 0n;
}

export function discoveryTag(pub: Point<bigint>): Fr {
  return new Fr(pub[0]);
}

async function rollToEvenY(
  derive: (index: bigint) => Promise<Fr>,
  startIndex: bigint,
): Promise<CanonicalAddress> {
  for (let attempt = 0n; attempt < MAX_INDEX_ROLL; attempt++) {
    const index = startIndex + attempt;
    const pub = publicKey(await derive(index));
    if (isEvenY(pub)) {
      return { index, pub, tag: discoveryTag(pub) };
    }
  }
  throw new Error(
    `even-y discovery tag not found within ${MAX_INDEX_ROLL} indices from ${startIndex}`,
  );
}

export function canonicalIncomingAddress(
  sk_view: Fr,
  startIndex: bigint,
): Promise<CanonicalAddress> {
  return rollToEvenY((index) => deriveIncomingKey(sk_view, index), startIndex);
}

export function canonicalSelfTag(
  sk_view: Fr,
  startIndex: bigint,
): Promise<CanonicalAddress> {
  return rollToEvenY(
    (index) => deriveSelfEphemeral(sk_view, index),
    startIndex,
  );
}
