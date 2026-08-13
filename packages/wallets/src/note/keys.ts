import { Fr } from "@aztec/foundation/fields";
import { type DerivedEph, asDerivedEph } from "../types/ephemeral.js";
import {
  Base8,
  inCurve,
  mulPointEscalar,
  Point,
  subOrder,
} from "@zk-kit/baby-jubjub";
import { Kdf } from "../crypto/Kdf.js";
import { Poseidon } from "../crypto/Poseidon.js";
import { toFr } from "../crypto/fields.js";
import { toBjjScalar } from "../crypto/index.js";

const VIEW_LABEL = "hisoka.view";
const IN_KEY_LABEL = "hisoka.inKey";
const SELF_EPH_LABEL = "hisoka.selfEph";
const SELF_SPEND_LABEL = "hisoka.selfSpend";
const PUB_IN_LABEL = "hisoka.pubIn";

// Only guards a non-terminating even-y roll; each index is even-y with prob ~1/2.
const MAX_INDEX_ROLL = 256n;

export interface CanonicalAddress {
  index: bigint;
  pub: Point<bigint>;
  tag: Fr;
}

/** Carries no discovery tag: a public memo publishes both owner coordinates, so nothing is derived from `pub.x`. */
export interface PublicIncomingAddress {
  index: bigint;
  pub: Point<bigint>;
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
): Promise<DerivedEph> {
  return asDerivedEph(
    toBjjScalar(await Kdf.derive(SELF_EPH_LABEL, sk_view, toFr(index))),
  );
}

export async function deriveSelfSpendKey(sk_view: Fr): Promise<Fr> {
  return toBjjScalar(await Kdf.derive(SELF_SPEND_LABEL, sk_view));
}

/** Separate label from `deriveIncomingKey` on purpose: a public transfer publishes its owner point in
 *  calldata, and the incoming family's `pub.x` is the private discovery tag, so sharing one family would
 *  retroactively deanonymize every private payment made to that index. */
export async function derivePublicIncomingKey(
  sk_view: Fr,
  index: bigint,
): Promise<Fr> {
  return toBjjScalar(await Kdf.derive(PUB_IN_LABEL, sk_view, toFr(index)));
}

export function publicKey(scalar: Fr): Point<bigint> {
  return mulPointEscalar(Base8, scalar.toBigInt());
}

export async function pubkeyOwner(pub: Point<bigint>): Promise<Fr> {
  return Poseidon.hash([new Fr(pub[0]), new Fr(pub[1])]);
}

// A discovery tag is the point's .x, which aliases (x, +/-y); injective only for even y (ref: intmax2 utils/key.rs).
export function isEvenY(pub: Point<bigint>): boolean {
  return (pub[1] & 1n) === 0n;
}

// BabyJubJub coordinate field (= BN254 Fr) + twisted-Edwards params a*x^2 + y^2 = 1 + d*x^2*y^2 (EIP-2494).
const BJJ_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const BJJ_A = 168700n;
const BJJ_D = 168696n;

function modP(x: bigint): bigint {
  return ((x % BJJ_P) + BJJ_P) % BJJ_P;
}

function powP(base: bigint, exp: bigint): bigint {
  let r = 1n;
  let b = modP(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % BJJ_P;
    b = (b * b) % BJJ_P;
    e >>= 1n;
  }
  return r;
}

function invP(x: bigint): bigint {
  const r = modP(x);
  if (r === 0n) throw new Error("recoverEvenY: division by zero");
  return powP(r, BJJ_P - 2n);
}

// Tonelli-Shanks sqrt mod BJJ_P (p == 1 mod 4, 2-adicity 28, so the (p+1)/4 shortcut does not apply).
function sqrtP(n: bigint): bigint {
  const a = modP(n);
  if (a === 0n) return 0n;
  if (powP(a, (BJJ_P - 1n) / 2n) !== 1n) {
    throw new Error("recoverEvenY: x has no y on the curve (non-residue)");
  }
  let q = BJJ_P - 1n;
  let s = 0n;
  while ((q & 1n) === 0n) {
    q >>= 1n;
    s += 1n;
  }
  let z = 2n;
  while (powP(z, (BJJ_P - 1n) / 2n) !== BJJ_P - 1n) z += 1n;
  let m = s;
  let c = powP(z, q);
  let t = powP(a, q);
  let r = powP(a, (q + 1n) / 2n);
  while (t !== 1n) {
    let i = 0n;
    let t2 = t;
    while (t2 !== 1n) {
      t2 = (t2 * t2) % BJJ_P;
      i += 1n;
      if (i === m) throw new Error("recoverEvenY: Tonelli-Shanks failed");
    }
    const b = powP(c, 1n << (m - i - 1n));
    m = i;
    c = (b * b) % BJJ_P;
    t = (t * c) % BJJ_P;
    r = (r * b) % BJJ_P;
  }
  return r;
}

// Mirrors Noir `even_y::is_even_y`. On-curve only, NOT subgroup-checked: caller MUST assertValidPoint before scalar-mul.
export function recoverEvenY(x: bigint): Point<bigint> {
  const x2 = modP(x * x);
  const num = modP(1n - modP(BJJ_A * x2));
  const den = modP(1n - modP(BJJ_D * x2));
  const y2 = modP(num * invP(den));
  let y = sqrtP(y2);
  if ((y & 1n) !== 0n) y = modP(BJJ_P - y);
  return [modP(x), y];
}

export function discoveryTag(pub: Point<bigint>): Fr {
  return new Fr(pub[0]);
}

/** Shared by the standard and multisig address paths: the tag is `pub.x`, so `pub` must be even-y for a
 *  single coordinate to identify the point. An index whose key lands on odd y is skipped, never patched. */
export async function rollToEvenY(
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

/** DarkPool `_isValidBjjPoint` checks the curve equation only; a memo owner outside the prime-order
 *  subgroup is reachable by no `public_claim` witness, so its escrow is unrecoverable. */
export function assertBjjSubgroupPoint(
  pub: Point<bigint>,
  subject: string,
): void {
  if (!inCurve(pub)) {
    throw new Error(`${subject} is not on the BabyJubJub curve.`);
  }
  if (pub[0] === 0n && pub[1] === 1n) {
    throw new Error(`${subject} is the identity.`);
  }
  const [ox, oy] = mulPointEscalar(pub, subOrder);
  if (ox !== 0n || oy !== 1n) {
    throw new Error(`${subject} is not in the prime-order subgroup.`);
  }
}

/** No even-y roll: even-y exists so a lone `pub.x` identifies the point, but `publicTransfer` publishes
 *  ownerX AND ownerY and `public_claim` binds both, so the point is already determined. Rolling would
 *  discard half the index space and silently renumber the caller's address for no gain. */
export async function canonicalPublicAddress(
  sk_view: Fr,
  index: bigint,
): Promise<PublicIncomingAddress> {
  const pub = publicKey(await derivePublicIncomingKey(sk_view, index));
  assertBjjSubgroupPoint(pub, `Public receiving key at index ${index}`);
  return { index, pub };
}
