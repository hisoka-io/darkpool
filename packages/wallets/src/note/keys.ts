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

// Recover the even-y BabyJubJub point from its x coordinate. Emitters canonicalize eph_pub to even-y, so y is
// uniquely recoverable from x alone (exactly one of y, p-y is even). Mirrors the Noir `even_y::is_even_y` rule.
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
